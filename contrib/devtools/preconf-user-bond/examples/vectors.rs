//! Deterministic, valueless fixtures for JK's native interpreter. No RPC or funds.
#[path = "../tests/common/mod.rs"]
mod common;
use common::*;
use elements::{encode, hashes::Hash, Transaction};
use elementsplus_preconf::{
    cooperative_action, elements, penalty_action, unilateral_action, Action,
};
use serde_json::{json, Value};

fn fixture(name: &str, mut tx: Transaction, action: &Action) -> Value {
    let env = env_for(bond(), tx.clone());
    let stack = bond().satisfy(&env, action).expect("valid fixture");
    tx.input[0].witness.script_witness = stack.clone();
    json!({"name": name,
        "genesis": hex::encode(config().genesis.as_byte_array()),
        "cmr": hex::encode(&stack[2]), "control": hex::encode(&stack[3]),
        "program": hex::encode(&stack[1]), "witness": hex::encode(&stack[0]),
        "raw_transaction": hex::encode(encode::serialize(&tx)),
        "txid": hex::encode(tx.txid().as_byte_array()),
        "version": tx.version, "lock_time": tx.lock_time.to_consensus_u32(),
        "inputs": tx.input.iter().map(|i| json!({
            "txid": hex::encode(i.previous_output.txid.as_byte_array()),
            "vout": i.previous_output.vout, "sequence": i.sequence.to_consensus_u32(),
            "asset": hex::encode(encode::serialize(&bond().funding_output().asset)),
            "value": hex::encode(encode::serialize(&bond().funding_output().value)),
            "script": hex::encode(bond().script_pubkey().as_bytes()),
        })).collect::<Vec<_>>(),
        "outputs": tx.output.iter().map(|o| json!({
            "asset": hex::encode(encode::serialize(&o.asset)),
            "value": hex::encode(encode::serialize(&o.value)),
            "script": hex::encode(o.script_pubkey.as_bytes()),
        })).collect::<Vec<_>>()
    })
}

fn main() {
    let (a, b) = evidence();
    let penalty = fixture(
        "penalty",
        penalty_env().tx().clone(),
        &penalty_action(&a, &b),
    );
    let tx = refund(config().refund_height);
    let digest = sighash(&env_for(bond(), tx.clone()));
    let unilateral = fixture(
        "unilateral",
        tx.clone(),
        &unilateral_action(&sign(digest, 1)),
    );
    let cooperative = fixture(
        "cooperative",
        tx,
        &cooperative_action(&sign(digest, 1), &sign(digest, 2)),
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "warning": "PUBLIC TEST KEYS, SYNTHETIC GENESIS/ASSET. DO NOT FUND.",
            "node_commit": "4041a8ba5d9c0870dbe22c188bce28410c10348a",
            "compiler": "simplicityhl 0.7.2 / simplicity-lang 0.8.0",
            "vectors": [penalty, unilateral, cooperative]
        }))
        .unwrap()
    );
}
