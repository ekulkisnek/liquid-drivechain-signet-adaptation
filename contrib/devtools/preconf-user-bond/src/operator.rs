//! Fixed-session PRECONFER bond. Does not change the existing user-bond format.
use super::{bond_environment, bond_taproot, satisfy_bond, signature_type, word, Action};
use crate::{elements, simplicity};
use elements::{
    confidential,
    hashes::{sha256, Hash, HashEngine},
    secp256k1_zkp::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey},
    taproot::ControlBlock,
    AssetId, BlockHash, OutPoint, Script, Transaction, TxOut, Txid,
};
use serde::{Deserialize, Serialize};
use simplicity::{
    jet::elements::{ElementsEnv, ElementsUtxo},
    Cmr,
};
use simplicityhl::{
    str::WitnessName,
    types::{ResolvedType, TypeConstructible},
    value::{UIntValue, ValueConstructible},
    Arguments, CompiledProgram,
};
use std::{collections::HashMap, sync::Arc};

pub const CONTRACT: &str = include_str!("../contracts/operator_bond.simf");
pub const DOMAIN: &[u8] = b"ECX/PreconfOperatorBond/Promise/v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(with = "display")]
    pub genesis: BlockHash,
    #[serde(with = "display")]
    pub fee_asset: AssetId,
    #[serde(with = "display")]
    pub preconfer: XOnlyPublicKey,
    #[serde(with = "outpoint")]
    pub protected_output: OutPoint,
    // Decimal string on the wire: do not lose u64 precision in browser JSON.
    #[serde(with = "display")]
    pub epoch: u64,
    pub collateral: u64,
    pub active_until: u32,
    pub refund_height: u32,
}

impl Config {
    pub fn compile(&self) -> Result<Bond, String> {
        if self.protected_output.is_null()
            || self.collateral == 0
            || self.collateral > 2_100_000_000_000_000
            || self.active_until == 0
            || self.active_until >= self.refund_height
            || self.refund_height >= 500_000_000
        {
            return Err("invalid operator bond parameters".into());
        }
        let args = Arguments::from(
            [
                ("DOMAIN", word(sha256::Hash::hash(DOMAIN).as_byte_array())),
                ("GENESIS", word(self.genesis.as_byte_array())),
                (
                    "FEE_ASSET",
                    word(&self.fee_asset.into_inner().to_byte_array()),
                ),
                ("PRECONFER", word(&self.preconfer.serialize())),
                (
                    "PROTECTED_TXID",
                    word(self.protected_output.txid.as_byte_array()),
                ),
                (
                    "PROTECTED_VOUT",
                    UIntValue::from(self.protected_output.vout).into(),
                ),
                ("EPOCH", UIntValue::from(self.epoch).into()),
                ("COLLATERAL", UIntValue::from(self.collateral).into()),
                ("ACTIVE_UNTIL", UIntValue::from(self.active_until).into()),
                ("REFUND_HEIGHT", UIntValue::from(self.refund_height).into()),
            ]
            .into_iter()
            .map(|(k, v)| (WitnessName::from_str_unchecked(k), v))
            .collect::<HashMap<_, _>>(),
        );
        let program = CompiledProgram::new(
            CONTRACT,
            args,
            false,
            Box::new(simplicityhl::ast::ElementsJetHinter),
        )?;
        let cmr = program.commit().cmr();
        let (script, control) = bond_taproot(cmr)?;
        Ok(Bond {
            config: self.clone(),
            program,
            cmr,
            control,
            script,
        })
    }
}

pub struct Bond {
    config: Config,
    program: CompiledProgram,
    cmr: Cmr,
    control: ControlBlock,
    script: Script,
}

impl Bond {
    pub fn config(&self) -> &Config {
        &self.config
    }
    pub fn script_pubkey(&self) -> &Script {
        &self.script
    }
    pub fn cmr(&self) -> Cmr {
        self.cmr
    }
    pub fn funding_output(&self) -> TxOut {
        TxOut {
            asset: confidential::Asset::Explicit(self.config.fee_asset),
            value: confidential::Value::Explicit(self.config.collateral),
            nonce: confidential::Nonce::Null,
            script_pubkey: self.script.clone(),
            witness: Default::default(),
        }
    }
    pub fn digest(&self, collateral: OutPoint, spend: Txid) -> [u8; 32] {
        let c = &self.config;
        let mut h = sha256::Hash::engine();
        for bytes in [
            sha256::Hash::hash(DOMAIN).as_byte_array().as_slice(),
            c.genesis.as_byte_array(),
            collateral.txid.as_byte_array(),
            &collateral.vout.to_be_bytes(),
            sha256::Hash::hash(self.script.as_bytes()).as_byte_array(),
            c.protected_output.txid.as_byte_array(),
            &c.protected_output.vout.to_be_bytes(),
            &c.epoch.to_be_bytes(),
            &c.active_until.to_be_bytes(),
            &c.refund_height.to_be_bytes(),
            spend.as_byte_array(),
        ] {
            h.input(bytes);
        }
        sha256::Hash::from_engine(h).to_byte_array()
    }
    /// Signature evidence only: NOT a chain, transaction validity, or funding check.
    pub fn verify(&self, receipt: &Receipt) -> Result<(), String> {
        if receipt.bond.is_null() || receipt.bond == self.config.protected_output {
            return Err("bond must be separate from principal".into());
        }
        let signature =
            Signature::from_slice(&receipt.signature).map_err(|_| "invalid signature encoding")?;
        Secp256k1::verification_only()
            .verify_schnorr(
                &signature,
                &Message::from_digest(self.digest(receipt.bond, receipt.txid)),
                &self.config.preconfer,
            )
            .map_err(|_| "invalid preconfer promise".into())
    }
    pub fn penalty_transaction(&self, collateral: OutPoint) -> Result<Transaction, String> {
        if collateral.is_null() || collateral == self.config.protected_output {
            return Err("bond must be separate from principal".into());
        }
        Ok(Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![elements::TxIn {
                previous_output: collateral,
                sequence: elements::Sequence::ENABLE_LOCKTIME_NO_RBF,
                ..Default::default()
            }],
            output: vec![TxOut::new_fee(
                self.config.collateral,
                self.config.fee_asset,
            )],
        })
    }
    pub fn environment(
        &self,
        tx: Transaction,
        utxos: Vec<ElementsUtxo>,
        genesis: BlockHash,
    ) -> Result<ElementsEnv<Arc<Transaction>>, String> {
        bond_environment(tx, utxos, genesis, self.cmr, &self.control)
    }
    pub fn satisfy(
        &self,
        env: &ElementsEnv<Arc<Transaction>>,
        action: &Action,
    ) -> Result<Vec<Vec<u8>>, String> {
        satisfy_bond(&self.program, &self.control, env, action)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    #[serde(with = "outpoint")]
    pub bond: OutPoint,
    #[serde(with = "display")]
    pub txid: Txid,
    #[serde(with = "signature_hex")]
    pub signature: [u8; 64],
}

impl Receipt {
    fn witness(&self) -> Action {
        Action::tuple([
            word(self.txid.as_byte_array()),
            Action::byte_array(self.signature),
        ])
    }
}
fn evidence_type() -> ResolvedType {
    let promise = ResolvedType::tuple([ResolvedType::u256(), signature_type()]);
    ResolvedType::tuple([promise.clone(), promise])
}
pub fn penalty_action(first: &Receipt, second: &Receipt) -> Result<Action, String> {
    if first.bond != second.bond || first.txid == second.txid {
        return Err("not same-bond conflicting promises".into());
    }
    Ok(Action::left(
        Action::tuple([first.witness(), second.witness()]),
        signature_type(),
    ))
}
pub fn refund_action(signature: &[u8; 64]) -> Action {
    Action::right(evidence_type(), Action::byte_array(*signature))
}

pub(crate) mod display {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::{fmt::Display, str::FromStr};
    pub fn serialize<T: Display, S: Serializer>(v: &T, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }
    pub fn deserialize<'de, T: FromStr + Display, D: Deserializer<'de>>(
        d: D,
    ) -> Result<T, D::Error> {
        let text = String::deserialize(d)?;
        let v: T = text
            .parse()
            .map_err(|_| serde::de::Error::custom("invalid value"))?;
        if v.to_string() != text {
            return Err(serde::de::Error::custom("noncanonical value"));
        }
        Ok(v)
    }
}

// Explicit RPC-style wire format, independent of rust-elements' Display prefix.
pub(crate) mod outpoint {
    use crate::elements::OutPoint;
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &OutPoint, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{}:{}", v.txid, v.vout))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<OutPoint, D::Error> {
        let text = String::deserialize(d)?;
        let v: OutPoint = text
            .parse()
            .map_err(|_| serde::de::Error::custom("invalid outpoint"))?;
        if format!("{}:{}", v.txid, v.vout) != text {
            return Err(serde::de::Error::custom("noncanonical outpoint"));
        }
        Ok(v)
    }
}
mod signature_hex {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let text = String::deserialize(d)?;
        let mut out = [0; 64];
        hex::decode_to_slice(&text, &mut out)
            .map_err(|_| serde::de::Error::custom("invalid signature"))?;
        if hex::encode(out) != text {
            return Err(serde::de::Error::custom("noncanonical signature"));
        }
        Ok(out)
    }
}
