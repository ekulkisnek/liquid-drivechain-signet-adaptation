#![allow(dead_code)]
pub mod operator;
// Public, deterministic TEST KEYS ONLY. Never fund these on any network.
use elements::{
    confidential,
    hashes::Hash,
    secp256k1_zkp::{Keypair, Message, Secp256k1, SecretKey},
    AssetId, BlockHash, OutPoint, Script, Transaction, Txid,
};
use elementsplus_preconf::{elements, simplicity, Authorization, Bond, Config};
use simplicity::jet::elements::{ElementsEnv, ElementsUtxo};
use std::sync::{Arc, OnceLock};

pub fn key(n: u8) -> Keypair {
    let mut secret = [0; 32];
    secret[31] = n;
    Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&secret).unwrap())
}

pub fn sign(digest: [u8; 32], n: u8) -> [u8; 64] {
    *Secp256k1::new()
        .sign_schnorr_no_aux_rand(&Message::from_digest(digest), &key(n))
        .as_ref()
}

pub fn config() -> Config {
    Config {
        genesis: BlockHash::from_byte_array([0x11; 32]),
        fee_asset: AssetId::from_byte_array([0x22; 32]),
        owner: key(1).x_only_public_key().0,
        matcher: key(2).x_only_public_key().0,
        protected_output: OutPoint {
            txid: Txid::from_byte_array([0x33; 32]),
            vout: 3,
        },
        epoch: 7,
        collateral: 100_000,
        active_until: 1_000,
        refund_height: 1_010,
    }
}

pub fn bond() -> &'static Bond {
    static BOND: OnceLock<Bond> = OnceLock::new();
    BOND.get_or_init(|| config().compile().expect("contract compiles"))
}

pub fn collateral() -> OutPoint {
    OutPoint {
        txid: Txid::from_byte_array([0x44; 32]),
        vout: 4,
    }
}

pub fn transfer(recipient: u8) -> Transaction {
    Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![elements::TxIn {
            previous_output: config().protected_output,
            ..Default::default()
        }],
        output: vec![elements::TxOut {
            asset: confidential::Asset::Explicit(AssetId::from_byte_array([0x55; 32])),
            value: confidential::Value::Explicit(10_000),
            nonce: confidential::Nonce::Null,
            script_pubkey: Script::from(
                vec![0x00, 0x14]
                    .into_iter()
                    .chain([recipient; 20])
                    .collect::<Vec<_>>(),
            ),
            witness: Default::default(),
        }],
    }
}

pub fn authorization(bond: &Bond, output: OutPoint, txid: Txid) -> Authorization {
    let digest = bond.receipt_digest(output, txid);
    Authorization {
        spend_txid: txid,
        owner_signature: sign(digest, 1),
        matcher_signature: sign(digest, 2),
    }
}

pub fn evidence() -> (Authorization, Authorization) {
    (
        authorization(bond(), collateral(), transfer(1).txid()),
        authorization(bond(), collateral(), transfer(2).txid()),
    )
}

pub fn env_for(b: &Bond, tx: Transaction) -> ElementsEnv<Arc<Transaction>> {
    let utxos = vec![ElementsUtxo::from(b.funding_output()); tx.input.len()];
    b.environment(tx, utxos, b.config().genesis).unwrap()
}

pub fn penalty_env() -> ElementsEnv<Arc<Transaction>> {
    env_for(bond(), bond().penalty_transaction(collateral()).unwrap())
}

pub fn refund(height: u32) -> Transaction {
    let mut tx = bond().penalty_transaction(collateral()).unwrap();
    tx.lock_time = elements::LockTime::from_height(height).unwrap();
    let mut pay = bond().funding_output();
    pay.script_pubkey = transfer(1).output[0].script_pubkey.clone();
    pay.value = confidential::Value::Explicit(config().collateral - 500);
    tx.output = vec![pay, elements::TxOut::new_fee(500, config().fee_asset)];
    tx
}

pub fn sighash(env: &ElementsEnv<Arc<Transaction>>) -> [u8; 32] {
    env.c_tx_env().sighash_all().to_byte_array()
}
