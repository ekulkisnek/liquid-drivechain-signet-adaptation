//! PUBLIC TEST KEYS ONLY. Fixture adapter for the isolated functional test.
#[path = "../tests/common/mod.rs"]
mod common;
use common::*;
use elements::{encode, OutPoint, Script, Transaction};
use elementsplus_preconf::{
    check_authorized_transaction, cooperative_action, elements, penalty_action, unilateral_action,
};
use serde_json::{json, Value};
use std::{io, process::Command, str::FromStr};

fn main() {
    let r: Value = serde_json::from_reader(io::stdin()).unwrap();
    assert_eq!(r["chain"], "elementsregtest");
    let protected = OutPoint::from_str(r["protected"].as_str().unwrap()).unwrap();
    if r["op"] == "validate" {
        let tx: Transaction =
            encode::deserialize(&hex::decode(r["hex"].as_str().unwrap()).unwrap()).unwrap();
        let mut cli = Command::new(r["cli"].as_str().unwrap());
        cli.arg("-chain=elementsregtest")
            .arg(format!("-datadir={}", r["datadir"].as_str().unwrap()));
        println!(
            "{}",
            match check_authorized_transaction(protected, &tx, cli) {
                Ok(txid) => json!({"txid": txid.to_string()}),
                Err(error) => json!({"error": error}),
            }
        );
        return;
    }
    let mut c = config();
    c.genesis = r["genesis"].as_str().unwrap().parse().unwrap();
    c.fee_asset = r["asset"].as_str().unwrap().parse().unwrap();
    c.protected_output = protected;
    c.active_until = r["active_until"].as_u64().unwrap() as u32;
    c.refund_height = c.active_until + 10;
    let b = c.compile().unwrap();
    if r["op"] == "script" {
        println!(
            "{}",
            json!({"script": hex::encode(b.script_pubkey().as_bytes())})
        );
        return;
    }
    let outpoint = r["bond"].as_str().unwrap().parse().unwrap();
    let mut tx = b.penalty_transaction(outpoint).unwrap();
    let action = if r["op"] == "penalty" {
        let a = authorization(&b, outpoint, r["txid_a"].as_str().unwrap().parse().unwrap());
        let z = authorization(&b, outpoint, r["txid_b"].as_str().unwrap().parse().unwrap());
        penalty_action(&a, &z)
    } else {
        tx.lock_time = elements::LockTime::from_height(c.refund_height).unwrap();
        let mut output = b.funding_output();
        output.script_pubkey =
            Script::from(hex::decode(r["destination"].as_str().unwrap()).unwrap());
        output.value = elements::confidential::Value::Explicit(c.collateral - 500);
        tx.output = vec![output, elements::TxOut::new_fee(500, c.fee_asset)];
        let digest = sighash(&env_for(&b, tx.clone()));
        if r["op"] == "cooperative" {
            cooperative_action(&sign(digest, 1), &sign(digest, 2))
        } else {
            assert_eq!(r["op"], "unilateral");
            unilateral_action(&sign(digest, 1))
        }
    };
    tx.input[0].witness.script_witness = b.satisfy(&env_for(&b, tx.clone()), &action).unwrap();
    println!("{}", json!({"hex": hex::encode(encode::serialize(&tx))}));
}
