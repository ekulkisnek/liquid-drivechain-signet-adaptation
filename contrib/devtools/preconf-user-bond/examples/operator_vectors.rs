//! Public TEST KEYS, synthetic genesis/asset, no RPC or real funds.
#[path = "../tests/common/mod.rs"]
mod common;
use common::operator::*;
use common::{collateral, sighash, sign};
use elementsplus_preconf::{
    elements::{encode, hashes::Hash, Transaction},
    operator::{penalty_action, refund_action},
    Action,
};
use serde_json::{json, Value};

fn fixture(name: &str, mut tx: Transaction, action: &Action) -> Value {
    let stack = bond()
        .satisfy(&env_for(bond(), tx.clone()), action)
        .unwrap();
    tx.input[0].witness.script_witness = stack.clone();
    json!({"name":name,"genesis":hex::encode(config().genesis.as_byte_array()),
        "cmr":hex::encode(&stack[2]),"control":hex::encode(&stack[3]),
        "program":hex::encode(&stack[1]),"witness":hex::encode(&stack[0]),
        "raw_transaction":hex::encode(encode::serialize(&tx)),
        "txid":hex::encode(tx.txid().as_byte_array()),"version":tx.version,
        "lock_time":tx.lock_time.to_consensus_u32(),
        "inputs":tx.input.iter().map(|i|json!({
            "txid":hex::encode(i.previous_output.txid.as_byte_array()),"vout":i.previous_output.vout,
            "sequence":i.sequence.to_consensus_u32(),
            "asset":hex::encode(encode::serialize(&bond().funding_output().asset)),
            "value":hex::encode(encode::serialize(&bond().funding_output().value)),
            "script":hex::encode(bond().script_pubkey().as_bytes()),
        })).collect::<Vec<_>>(),
        "outputs":tx.output.iter().map(|o|json!({
            "asset":hex::encode(encode::serialize(&o.asset)),"value":hex::encode(encode::serialize(&o.value)),
            "script":hex::encode(o.script_pubkey.as_bytes()),
        })).collect::<Vec<_>>()
    })
}

fn main() {
    let (a, b) = evidence();
    let penalty = fixture(
        "operator penalty",
        penalty_env().tx().clone(),
        &penalty_action(&a, &b).unwrap(),
    );
    let tx = refund(config().refund_height);
    let digest = sighash(&env_for(bond(), tx.clone()));
    let refund = fixture("operator refund", tx, &refund_action(&sign(digest, 2)));
    // The optional relay feature is not necessary for interpreter fixtures.
    #[cfg(not(feature = "relay"))]
    let profile_id = None::<String>;
    #[cfg(feature = "relay")]
    let profile_id = {
        use elementsplus_preconf::relay::{Profile, Session};
        Some(
            Profile {
                version: 1,
                sessions: vec![Session {
                    bond: collateral(),
                    config: config(),
                }],
            }
            .validate()
            .unwrap()
            .id
            .clone(),
        )
    };
    println!("{}",serde_json::to_string_pretty(&json!({
        "warning":"PUBLIC TEST KEYS, SYNTHETIC GENESIS/ASSET. DO NOT FUND.",
        "profile":{"version":1,"sessions":[{"bond":format!("{}:{}",collateral().txid,collateral().vout),"config":config()}]},
        "profile_id":profile_id,"receipts":[a,b],"vectors":[penalty,refund],
    })).unwrap());
}
