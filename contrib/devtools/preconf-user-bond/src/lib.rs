//! Experimental separate-collateral covenant. No networking, wallet key storage,
//! live-chain defaults, matcher service, or production preconfirmation claims.
//! See PROTOCOL.md for the deliberately restricted, fixed-session trust model.

use std::{str::FromStr, sync::Arc};

use elements::{
    confidential,
    hashes::{sha256, Hash, HashEngine},
    secp256k1_zkp::{Secp256k1, XOnlyPublicKey},
    taproot::{ControlBlock, TaprootBuilder},
    AssetId, BlockHash, OutPoint, Script, Transaction, TxOut,
};
use simplicity::{
    jet::elements::{ElementsEnv, ElementsUtxo},
    BitMachine, Cmr,
};
pub use simplicityhl::{elements, simplicity};
use simplicityhl::{Arguments, CompiledProgram, WitnessValues};

pub const CONTRACT: &str = include_str!("../contracts/user_bond.simf");
pub const RECEIPT_DOMAIN: &[u8] = b"ECX/PreconfUserBond/TransferAuthorization/v1";
// BIP341 NUMS point: x coordinate of lift_x(SHA256(uncompressed generator)).
// Nobody may supply a known-secret internal key; that would bypass the covenant.
const NUMS: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
pub const ACTION_TYPE: &str = "Either<((u256, Signature, Signature), (u256, Signature, Signature)), Either<(Signature, Signature), Signature>>";

#[derive(Clone, Debug)]
pub struct Config {
    pub genesis: BlockHash,
    pub fee_asset: AssetId,
    pub owner: XOnlyPublicKey,
    /// Must be independently checked against JK's deployed frozen profile.
    pub matcher: XOnlyPublicKey,
    pub protected_output: OutPoint,
    pub epoch: u64,
    pub collateral: u64,
    /// Off-chain acceptance cutoff, NOT a timestamp or a script clock reading.
    pub active_until: u32,
    /// Absolute sidechain height after a separately chosen challenge interval.
    pub refund_height: u32,
}

impl Config {
    pub fn validate(&self) -> Result<(), String> {
        if self.owner == self.matcher {
            return Err("owner and matcher must differ".into());
        }
        if self.collateral == 0 || self.collateral > 2_100_000_000_000_000 {
            return Err("collateral must be a positive money-range amount".into());
        }
        if self.active_until == 0
            || self.active_until >= self.refund_height
            || self.refund_height >= 500_000_000
        {
            return Err("require 0 < active_until < refund_height < 500000000".into());
        }
        if self.protected_output.is_null() {
            return Err("protected output must be a real outpoint".into());
        }
        Ok(())
    }

    pub fn compile(&self) -> Result<Bond, String> {
        self.validate()?;
        let word = |bytes: &[u8]| serde_json::json!({"type": "u256", "value": format!("0x{}", hex::encode(bytes))});
        let number = |n: u64, ty: &str| serde_json::json!({"type": ty, "value": n.to_string()});
        let args: Arguments = serde_json::from_str(
            &serde_json::json!({
                "DOMAIN": word(sha256::Hash::hash(RECEIPT_DOMAIN).as_byte_array()),
                "GENESIS": word(self.genesis.as_byte_array()),
                "FEE_ASSET": word(&self.fee_asset.into_inner().to_byte_array()),
                "OWNER": word(&self.owner.serialize()),
                "MATCHER": word(&self.matcher.serialize()),
                "PROTECTED_TXID": word(self.protected_output.txid.as_byte_array()),
                "PROTECTED_VOUT": number(self.protected_output.vout.into(), "u32"),
                "EPOCH": number(self.epoch, "u64"),
                "COLLATERAL": number(self.collateral, "u64"),
                "ACTIVE_UNTIL": number(self.active_until.into(), "u32"),
                "REFUND_HEIGHT": number(self.refund_height.into(), "u32"),
            })
            .to_string(),
        )
        .map_err(|e| e.to_string())?;
        let program = CompiledProgram::new(
            CONTRACT,
            args,
            false,
            Box::new(simplicityhl::ast::ElementsJetHinter),
        )?;
        let cmr = program.commit().cmr();
        let leaf = Script::from(cmr.as_ref().to_vec());
        let tree = TaprootBuilder::new()
            .add_leaf_with_ver(0, leaf.clone(), simplicity::leaf_version())
            .map_err(|e| e.to_string())?;
        let info = tree
            .finalize(
                &Secp256k1::verification_only(),
                XOnlyPublicKey::from_str(NUMS).map_err(|e| e.to_string())?,
            )
            .map_err(|_| "cannot finalize single-leaf Taproot tree")?;
        let control = info
            .control_block(&(leaf, simplicity::leaf_version()))
            .ok_or("missing single-leaf control block")?;
        Ok(Bond {
            config: self.clone(),
            program,
            cmr,
            script_pubkey: Script::new_v1_p2tr_tweaked(info.output_key()),
            control,
        })
    }
}

pub struct Bond {
    config: Config,
    program: CompiledProgram,
    cmr: Cmr,
    script_pubkey: Script,
    control: ControlBlock,
}

impl Bond {
    pub fn config(&self) -> &Config {
        &self.config
    }
    pub fn cmr(&self) -> Cmr {
        self.cmr
    }
    pub fn script_pubkey(&self) -> &Script {
        &self.script_pubkey
    }
    pub fn control_block(&self) -> &ControlBlock {
        &self.control
    }

    pub fn funding_output(&self) -> TxOut {
        TxOut {
            asset: confidential::Asset::Explicit(self.config.fee_asset),
            value: confidential::Value::Explicit(self.config.collateral),
            nonce: confidential::Nonce::Null,
            script_pubkey: self.script_pubkey.clone(),
            witness: Default::default(),
        }
    }

    /// Canonical signing digest. Integers are big-endian; hash bytes use their
    /// consensus/internal order, NOT the reversed display form of a txid.
    /// It binds the chain, concrete collateral outpoint, covenant, protected
    /// output, session/expiry and a full spending-transaction identifier.
    pub fn receipt_digest(&self, bond_outpoint: OutPoint, spend_txid: elements::Txid) -> [u8; 32] {
        let c = &self.config;
        let mut engine = sha256::Hash::engine();
        for bytes in [
            sha256::Hash::hash(RECEIPT_DOMAIN)
                .as_byte_array()
                .as_slice(),
            c.genesis.as_byte_array(),
            bond_outpoint.txid.as_byte_array(),
            &bond_outpoint.vout.to_be_bytes(),
            sha256::Hash::hash(self.script_pubkey.as_bytes()).as_byte_array(),
            c.protected_output.txid.as_byte_array(),
            &c.protected_output.vout.to_be_bytes(),
            &c.epoch.to_be_bytes(),
            &c.active_until.to_be_bytes(),
            &c.refund_height.to_be_bytes(),
            spend_txid.as_byte_array(),
        ] {
            engine.input(bytes);
        }
        sha256::Hash::from_engine(engine).to_byte_array()
    }

    /// One collateral input -> one explicit fee output. Never consumes principal.
    pub fn penalty_transaction(&self, bond_outpoint: OutPoint) -> Result<Transaction, String> {
        if bond_outpoint == self.config.protected_output || bond_outpoint.is_null() {
            return Err("collateral must be a separate, non-null output".into());
        }
        Ok(Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![elements::TxIn {
                previous_output: bond_outpoint,
                sequence: elements::Sequence::ENABLE_LOCKTIME_NO_RBF,
                ..Default::default()
            }],
            output: vec![TxOut::new_fee(
                self.config.collateral,
                self.config.fee_asset,
            )],
        })
    }

    /// Build an execution environment from caller-supplied chain data. This is
    /// not a chain lookup or proof that the supplied UTXO exists/is unspent.
    pub fn environment(
        &self,
        tx: Transaction,
        utxos: Vec<ElementsUtxo>,
        genesis: BlockHash,
    ) -> Result<ElementsEnv<Arc<Transaction>>, String> {
        if tx.input.is_empty() || utxos.len() != tx.input.len() {
            return Err("one authenticated UTXO description per input is required".into());
        }
        Ok(ElementsEnv::new(
            Arc::new(tx),
            utxos,
            0,
            self.cmr,
            self.control.clone(),
            None,
            genesis,
        ))
    }

    /// Compile, prune and execute the actual Simplicity program. Return its
    /// consensus witness stack, not merely a successful host-language check.
    /// Full node UTXO, timelock finality, and Taproot validation are separate.
    pub fn satisfy(
        &self,
        env: &ElementsEnv<Arc<Transaction>>,
        action: &str,
    ) -> Result<Vec<Vec<u8>>, String> {
        let witness: WitnessValues = serde_json::from_str(
            &serde_json::json!({
                "ACTION": {"type": ACTION_TYPE, "value": action}
            })
            .to_string(),
        )
        .map_err(|e| e.to_string())?;
        let satisfied = self.program.satisfy_with_env(witness, Some(env))?;
        let redeem = satisfied.redeem();
        let mut machine = BitMachine::for_program(redeem).map_err(|e| e.to_string())?;
        machine.exec(redeem, env).map_err(|e| e.to_string())?;
        let (program, witness) = redeem.to_vec_with_witness();
        Ok(vec![
            witness,
            program,
            self.cmr.as_ref().to_vec(),
            self.control.serialize(),
        ])
    }
}

#[derive(Clone, Debug)]
pub struct Authorization {
    pub spend_txid: elements::Txid,
    pub owner_signature: [u8; 64],
    pub matcher_signature: [u8; 64],
}

impl Authorization {
    fn witness(&self) -> String {
        format!(
            "(0x{}, 0x{}, 0x{})",
            hex::encode(self.spend_txid.as_byte_array()),
            hex::encode(self.owner_signature),
            hex::encode(self.matcher_signature)
        )
    }
}

pub fn penalty_action(first: &Authorization, second: &Authorization) -> String {
    format!("Left(({}, {}))", first.witness(), second.witness())
}

pub fn cooperative_action(owner: &[u8; 64], matcher: &[u8; 64]) -> String {
    format!(
        "Right(Left((0x{}, 0x{})))",
        hex::encode(owner),
        hex::encode(matcher)
    )
}

pub fn unilateral_action(owner: &[u8; 64]) -> String {
    format!("Right(Right(0x{}))", hex::encode(owner))
}

/// Validate the certificate subject before requesting signatures. This is a
/// necessary structural check, not full transaction/script/UTXO validation.
pub fn check_authorized_transaction(
    protected: OutPoint,
    tx: &Transaction,
) -> Result<elements::Txid, String> {
    if protected.is_null() || tx.output.is_empty() {
        return Err(
            "authorization requires a non-null protected output and transaction outputs".into(),
        );
    }
    if tx
        .input
        .iter()
        .filter(|i| !i.is_pegin && i.previous_output == protected)
        .count()
        != 1
    {
        return Err("authorization must spend its protected output exactly once".into());
    }
    if tx.input.iter().any(|i| i.is_pegin || i.has_issuance()) {
        return Err("pegin and issuance are outside this authorization prototype".into());
    }
    let mut outpoints = std::collections::HashSet::new();
    if tx
        .input
        .iter()
        .any(|i| i.previous_output.is_null() || !outpoints.insert(i.previous_output))
    {
        return Err("null or duplicate input outpoint".into());
    }
    Ok(tx.txid())
}
