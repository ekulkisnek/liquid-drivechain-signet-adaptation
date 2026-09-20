mod common;
use common::operator::*;
use common::{collateral, key, sighash, sign, transfer};
use elementsplus_preconf::{
    elements::{self, confidential, hashes::Hash, AssetId, BlockHash, Sequence, TxOut, Txid},
    operator::{penalty_action, refund_action, Receipt},
    simplicity::jet::elements::ElementsUtxo,
};

#[test]
fn preconfer_alone_is_accountable_and_principal_is_not_spent() {
    let (a, b) = evidence();
    bond().verify(&a).unwrap();
    bond().verify(&b).unwrap();
    for (first, second) in [(&a, &b), (&b, &a)] {
        let env = penalty_env();
        let stack = bond()
            .satisfy(&env, &penalty_action(first, second).unwrap())
            .unwrap();
        assert_eq!(stack.len(), 4);
        assert_eq!(stack[2], bond().cmr().as_ref());
        assert_eq!(stack[3].len(), 33); // single leaf, no alternative spending branch
        assert_eq!(stack[3][0] & 0xfe, 0xbe);
        assert_eq!(
            hex::encode(&stack[3][1..]),
            "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
        );
        assert_ne!(env.tx().input[0].previous_output, config().protected_output);
        assert!(env.tx().output[0].is_fee());
        assert_eq!(
            env.tx().output[0].value,
            confidential::Value::Explicit(config().collateral)
        );
    }
}

#[test]
fn every_operator_signature_is_required_and_user_signature_cannot_substitute() {
    for which in 0..4 {
        let (mut a, mut b) = evidence();
        match which {
            0 => a.signature[0] ^= 1,
            1 => b.signature[63] ^= 1,
            2 => a.signature = sign(bond().digest(a.bond, a.txid), 1),
            _ => b.txid = transfer(3).txid(),
        }
        assert!(bond().verify(&a).is_err() || bond().verify(&b).is_err());
        assert!(bond()
            .satisfy(&penalty_env(), &penalty_action(&a, &b).unwrap())
            .is_err());
    }
}

#[test]
fn same_transaction_is_not_slashable_even_with_randomized_signature() {
    use elements::secp256k1_zkp::{Message, Secp256k1};
    use simplicityhl::{
        types::{ResolvedType, TypeConstructible},
        value::{UIntValue, Value, ValueConstructible},
    };
    let (a, mut b) = evidence();
    b.txid = a.txid;
    b.signature = *Secp256k1::new()
        .sign_schnorr_with_aux_rand(
            &Message::from_digest(bond().digest(b.bond, b.txid)),
            &key(2),
            &[9; 32],
        )
        .as_ref();
    bond().verify(&b).unwrap();
    assert_ne!(a.signature, b.signature);
    assert!(penalty_action(&a, &b).is_err());
    // Bypass the friendly constructor; the on-chain program must enforce this too.
    let promise = |r: &Receipt| {
        Value::tuple([
            UIntValue::U256(simplicityhl::num::U256::from_byte_array(
                r.txid.to_byte_array(),
            ))
            .into(),
            Value::byte_array(r.signature),
        ])
    };
    let action = Value::left(
        Value::tuple([promise(&a), promise(&b)]),
        ResolvedType::array(ResolvedType::u8(), 64),
    );
    assert!(bond().satisfy(&penalty_env(), &action).is_err());
}

#[test]
fn domain_chain_session_and_outpoint_replay_rejected() {
    let (a, b) = evidence();
    let action = penalty_action(&a, &b).unwrap();
    let (old_a, _) = common::evidence();
    let mut from_user_format = a.clone();
    from_user_format.signature = old_a.matcher_signature;
    assert!(bond().verify(&from_user_format).is_err());
    for field in 0..10 {
        let mut c = config();
        match field {
            0 => c.genesis = BlockHash::from_byte_array([0x77; 32]),
            1 => c.fee_asset = AssetId::from_byte_array([0x77; 32]),
            2 => c.preconfer = key(3).x_only_public_key().0,
            3 => c.protected_output.txid = Txid::from_byte_array([0x77; 32]),
            4 => c.protected_output.vout += 1,
            5 => c.epoch += 1,
            6 => c.collateral += 1,
            7 => c.active_until += 1,
            8 => c.refund_height += 1,
            _ => (),
        }
        let other = c.compile().unwrap();
        let mut tx = other.penalty_transaction(collateral()).unwrap();
        if field == 9 {
            tx.input[0].previous_output.vout += 1;
        }
        assert!(
            other.satisfy(&env_for(&other, tx), &action).is_err(),
            "field {field}"
        );
    }
    let env = bond()
        .environment(
            penalty_env().tx().clone(),
            vec![bond().funding_output().into()],
            BlockHash::from_byte_array([0x77; 32]),
        )
        .unwrap();
    assert!(bond().satisfy(&env, &action).is_err());
}

#[test]
fn diversion_partial_burn_extra_io_and_asset_substitution_rejected() {
    let (a, b) = evidence();
    let action = penalty_action(&a, &b).unwrap();
    for attack in 0..9 {
        let mut tx = penalty_env().tx().clone();
        match attack {
            0 => tx.output[0].script_pubkey = transfer(9).output[0].script_pubkey.clone(),
            1 => tx.output[0].value = confidential::Value::Explicit(config().collateral - 1),
            2 => tx.output[0].value = confidential::Value::Explicit(config().collateral + 1),
            3 => {
                tx.output[0].asset =
                    confidential::Asset::Explicit(AssetId::from_byte_array([0x99; 32]))
            }
            4 => tx.output.push(TxOut::new_fee(0, config().fee_asset)),
            5 => tx.output.clear(),
            6 => tx.input.push(tx.input[0].clone()),
            7 => tx.input[0].asset_issuance.amount = confidential::Value::Explicit(1),
            _ => tx.input[0].asset_issuance.inflation_keys = confidential::Value::Explicit(1),
        }
        assert!(
            bond().satisfy(&env_for(bond(), tx), &action).is_err(),
            "attack {attack}"
        );
    }
}

#[test]
fn invalid_collateral_and_principal_consumption_rejected() {
    let (a, b) = evidence();
    let action = penalty_action(&a, &b).unwrap();
    for attack in 0..6 {
        let mut output = bond().funding_output();
        match attack {
            0 => output.asset = confidential::Asset::Explicit(AssetId::from_byte_array([0x99; 32])),
            1 => output.value = confidential::Value::Explicit(config().collateral - 1),
            2 => output.value = confidential::Value::Null,
            3 => output.asset = confidential::Asset::Null,
            4 => {
                output.asset = confidential::Asset::new_confidential(
                    &elements::secp256k1_zkp::Secp256k1::new(),
                    config().fee_asset,
                    confidential::AssetBlindingFactor::from_slice(&[1; 32]).unwrap(),
                )
            }
            _ => {
                output.value = confidential::Value::new_confidential_from_assetid(
                    &elements::secp256k1_zkp::Secp256k1::new(),
                    config().collateral,
                    config().fee_asset,
                    confidential::ValueBlindingFactor::from_slice(&[2; 32]).unwrap(),
                    confidential::AssetBlindingFactor::from_slice(&[1; 32]).unwrap(),
                )
            }
        }
        let env = bond()
            .environment(
                penalty_env().tx().clone(),
                vec![ElementsUtxo::from(output)],
                config().genesis,
            )
            .unwrap();
        assert!(bond().satisfy(&env, &action).is_err(), "attack {attack}");
    }
    let output = config().protected_output;
    assert!(bond().penalty_transaction(output).is_err());
    let a = receipt(output, transfer(1).txid());
    let b = receipt(output, transfer(2).txid());
    let mut tx = penalty_env().tx().clone();
    tx.input[0].previous_output = output;
    assert!(bond()
        .satisfy(&env_for(bond(), tx), &penalty_action(&a, &b).unwrap())
        .is_err());
}

#[test]
fn only_operator_can_refund_after_deadline_and_signature_commits_to_outputs() {
    let tx = refund(config().refund_height);
    let env = env_for(bond(), tx.clone());
    let sig = sign(sighash(&env), 2);
    bond().satisfy(&env, &refund_action(&sig)).unwrap();
    assert!(bond()
        .satisfy(&env, &refund_action(&sign(sighash(&env), 1)))
        .is_err());
    for attack in 0..3 {
        let mut tx = tx.clone();
        match attack {
            0 => {
                tx.lock_time = elements::LockTime::from_height(config().refund_height - 1).unwrap()
            }
            1 => tx.input[0].sequence = Sequence::MAX,
            _ => tx.output[0].script_pubkey = transfer(9).output[0].script_pubkey.clone(),
        }
        let env = env_for(bond(), tx);
        let action = if attack < 2 {
            refund_action(&sign(sighash(&env), 2))
        } else {
            refund_action(&sig)
        };
        assert!(bond().satisfy(&env, &action).is_err());
    }
}

#[test]
fn wire_format_is_canonical_and_preserves_epoch_precision() {
    let mut c = config();
    c.epoch = u64::MAX;
    let json = serde_json::to_string(&c).unwrap();
    assert!(json.contains("\"epoch\":\"18446744073709551615\""));
    assert_eq!(
        serde_json::from_str::<elementsplus_preconf::operator::Config>(&json)
            .unwrap()
            .epoch,
        u64::MAX
    );
    let (r, _) = evidence();
    let value = serde_json::to_value(&r).unwrap();
    assert_eq!(value["bond"], format!("{}:{}", r.bond.txid, r.bond.vout));
    assert_eq!(serde_json::from_value::<Receipt>(value.clone()).unwrap(), r);
    for attack in 0..4 {
        let mut v = value.clone();
        match attack {
            0 => v["secret"] = true.into(),
            1 => v["signature"] = "00".into(),
            2 => v["signature"] = hex::encode(r.signature).to_uppercase().into(),
            _ => v["bond"] = format!("{}:04", r.bond.txid).into(),
        }
        assert!(serde_json::from_value::<Receipt>(v).is_err());
    }
}

#[test]
fn synthetic_operator_cmr_is_pinned_and_distinct_from_user_bond() {
    assert_eq!(
        bond().cmr().to_string(),
        "b164ef4f9ccce13340a323c40daa12a2b97ed13f1403b0f3f954abb458c11040"
    );
    assert_ne!(bond().cmr(), common::bond().cmr());
}

#[test]
fn both_bonds_reject_incomplete_execution_environments() {
    for inputs in 0..=2 {
        for descriptions in 0..=2 {
            let mut tx = bond().penalty_transaction(collateral()).unwrap();
            tx.input = vec![tx.input[0].clone(); inputs];
            let expected = inputs != 0 && inputs == descriptions;
            let operator_utxos = vec![ElementsUtxo::from(bond().funding_output()); descriptions];
            let user_utxos =
                vec![ElementsUtxo::from(common::bond().funding_output()); descriptions];
            assert_eq!(
                bond()
                    .environment(tx.clone(), operator_utxos, config().genesis)
                    .is_ok(),
                expected,
            );
            assert_eq!(
                common::bond()
                    .environment(tx, user_utxos, config().genesis)
                    .is_ok(),
                expected,
            );
        }
    }
}
