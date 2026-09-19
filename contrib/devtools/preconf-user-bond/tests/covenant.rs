mod common;
use common::*;
use elements::{confidential, hashes::Hash, AssetId, BlockHash, Sequence, TxOut, Txid};
use elementsplus_preconf::{
    check_authorization_subject, cooperative_action, elements, penalty_action, simplicity,
    unilateral_action,
};
use simplicity::jet::elements::ElementsUtxo;

#[test]
fn two_owner_and_matcher_signed_conflicting_transfers_pay_all_collateral_as_fee() {
    let (a, b) = evidence();
    let env = penalty_env();
    let stack = bond().satisfy(&env, &penalty_action(&a, &b)).unwrap();
    assert_eq!(stack.len(), 4);
    assert_eq!(stack[2], bond().cmr().as_ref());
    assert_eq!(stack[3][0] & 0xfe, 0xbe);
    assert_eq!(env.tx().input[0].previous_output, collateral());
    assert_ne!(env.tx().input[0].previous_output, config().protected_output);
    assert!(env.tx().output[0].is_fee());
    assert_eq!(
        env.tx().output[0].value,
        confidential::Value::Explicit(config().collateral)
    );
    eprintln!(
        "penalty program={}B witness={}B cmr={}",
        stack[1].len(),
        stack[0].len(),
        bond().cmr()
    );
}

#[test]
fn swapped_evidence_order_is_valid() {
    let (a, b) = evidence();
    bond()
        .satisfy(&penalty_env(), &penalty_action(&b, &a))
        .unwrap();
}

#[test]
fn identical_transfer_is_not_misconduct_even_with_different_signatures() {
    let (a, mut b) = evidence();
    b.spend_txid = a.spend_txid;
    let digest = bond().receipt_digest(collateral(), a.spend_txid);
    let secp = elements::secp256k1_zkp::Secp256k1::new();
    b.owner_signature = *secp
        .sign_schnorr_with_aux_rand(
            &elements::secp256k1_zkp::Message::from_digest(digest),
            &key(1),
            &[9; 32],
        )
        .as_ref();
    b.matcher_signature = sign(digest, 2);
    assert_ne!(a.owner_signature, b.owner_signature);
    assert!(bond()
        .satisfy(&penalty_env(), &penalty_action(&a, &b))
        .is_err());
}

#[test]
fn every_signature_is_required_and_matcher_cannot_frame_owner() {
    for which in 0..4 {
        let (mut a, mut b) = evidence();
        let signature = match which {
            0 => &mut a.owner_signature,
            1 => &mut a.matcher_signature,
            2 => &mut b.owner_signature,
            _ => &mut b.matcher_signature,
        };
        signature[9] ^= 1;
        assert!(
            bond()
                .satisfy(&penalty_env(), &penalty_action(&a, &b))
                .is_err(),
            "signature {which}"
        );
    }
    let (a, mut b) = evidence();
    b.owner_signature = b.matcher_signature;
    assert!(bond()
        .satisfy(&penalty_env(), &penalty_action(&a, &b))
        .is_err());
}

#[test]
fn changed_transfer_after_signing_rejected() {
    let (a, mut b) = evidence();
    b.spend_txid = transfer(3).txid();
    assert!(bond()
        .satisfy(&penalty_env(), &penalty_action(&a, &b))
        .is_err());
}

#[test]
fn replay_on_another_collateral_output_rejected() {
    let (a, b) = evidence();
    for change_txid in [false, true] {
        let mut tx = penalty_env().tx().clone();
        if change_txid {
            tx.input[0].previous_output.txid = Txid::from_byte_array([0x66; 32]);
        } else {
            tx.input[0].previous_output.vout += 1;
        }
        assert!(bond()
            .satisfy(&env_for(bond(), tx), &penalty_action(&a, &b))
            .is_err());
    }
}

#[test]
fn replay_on_another_chain_or_covenant_rejected() {
    let (a, b) = evidence();
    let action = penalty_action(&a, &b);
    let tx = penalty_env().tx().clone();
    let env = bond()
        .environment(
            tx,
            vec![ElementsUtxo::from(bond().funding_output())],
            BlockHash::from_byte_array([0x77; 32]),
        )
        .unwrap();
    assert!(bond().satisfy(&env, &action).is_err());
    for field in 0..7 {
        let mut c = config();
        match field {
            0 => c.protected_output.vout += 1,
            1 => c.protected_output.txid = Txid::from_byte_array([0x66; 32]),
            2 => c.epoch += 1,
            3 => c.active_until += 1,
            4 => c.refund_height += 1,
            5 => c.matcher = key(3).x_only_public_key().0,
            _ => c.owner = key(3).x_only_public_key().0,
        }
        let other = c.compile().unwrap();
        let env = env_for(&other, other.penalty_transaction(collateral()).unwrap());
        assert!(other.satisfy(&env, &action).is_err(), "field {field}");
    }
}

#[test]
fn diversion_partial_burn_extra_output_wrong_asset_and_wrong_amount_rejected() {
    let (a, b) = evidence();
    let action = penalty_action(&a, &b);
    for attack in 0..7 {
        let mut tx = penalty_env().tx().clone();
        match attack {
            0 => tx.output[0].script_pubkey = transfer(9).output[0].script_pubkey.clone(),
            1 => tx.output[0].value = confidential::Value::Explicit(config().collateral - 1),
            2 => tx.output.push(TxOut::new_fee(0, config().fee_asset)),
            3 => {
                tx.output[0].asset =
                    confidential::Asset::Explicit(AssetId::from_byte_array([0x99; 32]))
            }
            4 => tx.output[0].value = confidential::Value::Explicit(config().collateral + 1),
            5 => tx.output.clear(),
            _ => tx.input.push(tx.input[0].clone()),
        }
        assert!(
            bond().satisfy(&env_for(bond(), tx), &action).is_err(),
            "attack {attack}"
        );
    }
}

#[test]
fn incorrect_or_confidential_collateral_rejected() {
    let (a, b) = evidence();
    let action = penalty_action(&a, &b);
    for attack in 0..6 {
        let mut output = bond().funding_output();
        let secp = elements::secp256k1_zkp::Secp256k1::new();
        match attack {
            0 => output.asset = confidential::Asset::Explicit(AssetId::from_byte_array([0x99; 32])),
            1 => output.value = confidential::Value::Explicit(config().collateral - 1),
            2 => output.value = confidential::Value::Null,
            3 => output.asset = confidential::Asset::Null,
            4 => {
                output.asset = confidential::Asset::new_confidential(
                    &secp,
                    config().fee_asset,
                    confidential::AssetBlindingFactor::from_slice(&[1; 32]).unwrap(),
                )
            }
            _ => {
                output.value = confidential::Value::new_confidential_from_assetid(
                    &secp,
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
                vec![output.into()],
                config().genesis,
            )
            .unwrap();
        assert!(bond().satisfy(&env, &action).is_err(), "attack {attack}");
    }
}

#[test]
fn principal_cannot_be_consumed_even_when_transaction_builder_is_bypassed() {
    let mut tx = penalty_env().tx().clone();
    tx.input[0].previous_output = config().protected_output;
    let a = authorization(bond(), config().protected_output, transfer(1).txid());
    let b = authorization(bond(), config().protected_output, transfer(2).txid());
    assert!(bond()
        .satisfy(&env_for(bond(), tx), &penalty_action(&a, &b))
        .is_err());
}

#[test]
fn pegin_and_issuance_cannot_be_hidden_in_penalty_input() {
    let (a, b) = evidence();
    let action = penalty_action(&a, &b);
    let mut tx = penalty_env().tx().clone();
    tx.input[0].asset_issuance.amount = confidential::Value::Explicit(1);
    assert!(bond().satisfy(&env_for(bond(), tx), &action).is_err());
    let mut tx = penalty_env().tx().clone();
    tx.input[0].asset_issuance.inflation_keys = confidential::Value::Explicit(1);
    assert!(bond().satisfy(&env_for(bond(), tx), &action).is_err());
    // Shape-valid synthetic pegin environment, not a valid parent inclusion proof.
    let mut tx = penalty_env().tx().clone();
    tx.input[0].is_pegin = true;
    tx.input[0].witness.pegin_witness = vec![
        config().collateral.to_le_bytes().to_vec(),
        elements::encode::serialize(&config().fee_asset),
        config().genesis.as_byte_array().to_vec(),
        vec![],
        vec![],
        vec![0; 80],
    ];
    assert!(tx.input[0].pegin_data().is_some());
    assert!(bond().satisfy(&env_for(bond(), tx), &action).is_err());
}

#[test]
fn reviewed_fixture_cmr_is_pinned() {
    assert_eq!(
        bond().cmr().to_string(),
        "397aa6803ceb30cc12b2853824ba0a9df863731f0ef42045faf47ecf227499ac"
    );
}

#[test]
fn complete_witness_serializes_and_commits_to_the_single_nums_tapleaf() {
    use elements::schnorr::TweakedPublicKey;
    use elements::secp256k1_zkp::{Secp256k1, XOnlyPublicKey};
    use elements::taproot::ControlBlock;
    let (a, b) = evidence();
    let env = penalty_env();
    let stack = bond().satisfy(&env, &penalty_action(&a, &b)).unwrap();
    let control = ControlBlock::from_slice(&stack[3]).unwrap();
    assert_eq!(
        control.serialize().len(),
        33,
        "no alternative script leaves"
    );
    assert_eq!(
        control.internal_key.to_string(),
        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
    );
    let key = TweakedPublicKey::new(
        XOnlyPublicKey::from_slice(&bond().script_pubkey().as_bytes()[2..]).unwrap(),
    );
    assert!(control.verify_taproot_commitment(
        &Secp256k1::verification_only(),
        &key,
        &elements::Script::from(stack[2].clone())
    ));
    assert!(!control.verify_taproot_commitment(
        &Secp256k1::verification_only(),
        &key,
        &elements::Script::from(vec![0; 32])
    ));
    let mut tx = env.tx().clone();
    tx.input[0].witness.script_witness = stack;
    let bytes = elements::encode::serialize(&tx);
    assert_eq!(
        elements::encode::deserialize::<elements::Transaction>(&bytes).unwrap(),
        tx
    );
}

#[test]
fn malformed_witness_does_not_get_a_signature_or_a_spend() {
    use simplicityhl::value::{Value, ValueConstructible};
    for action in [Value::unit(), Value::from(false), Value::byte_array([0])] {
        assert!(bond().satisfy(&penalty_env(), &action).is_err());
    }
}

#[test]
fn owner_recovers_without_matcher_after_deadline() {
    let env = env_for(bond(), refund(config().refund_height));
    bond()
        .satisfy(&env, &unilateral_action(&sign(sighash(&env), 1)))
        .unwrap();
}

#[test]
fn cooperative_release_after_deadline() {
    let env = env_for(bond(), refund(config().refund_height));
    let msg = sighash(&env);
    bond()
        .satisfy(&env, &cooperative_action(&sign(msg, 1), &sign(msg, 2)))
        .unwrap();
}

#[test]
fn neither_owner_nor_matcher_can_bypass_collateral_deadline() {
    let env = env_for(bond(), refund(config().refund_height - 1));
    let msg = sighash(&env);
    assert!(bond()
        .satisfy(&env, &cooperative_action(&sign(msg, 1), &sign(msg, 2)))
        .is_err());
    assert!(bond()
        .satisfy(&env, &unilateral_action(&sign(msg, 1)))
        .is_err());
}

#[test]
fn release_rejects_disabled_locktime_timestamp_and_wrong_signature() {
    for attack in 0..3 {
        let mut tx = refund(config().refund_height);
        if attack == 0 {
            tx.input[0].sequence = Sequence::MAX;
        }
        if attack == 1 {
            tx.lock_time = elements::LockTime::from_time(500_000_001).unwrap();
        }
        let env = env_for(bond(), tx);
        let key = if attack == 2 { 2 } else { 1 };
        assert!(
            bond()
                .satisfy(&env, &unilateral_action(&sign(sighash(&env), key)))
                .is_err(),
            "attack {attack}"
        );
    }
}

#[test]
fn release_signature_binds_destination_amount_fees_and_sequence() {
    let tx = refund(config().refund_height);
    let env = env_for(bond(), tx.clone());
    let action = unilateral_action(&sign(sighash(&env), 1));
    for attack in 0..4 {
        let mut modified = tx.clone();
        match attack {
            0 => modified.output[0].script_pubkey = transfer(8).output[0].script_pubkey.clone(),
            1 => modified.output[0].value = confidential::Value::Explicit(1),
            2 => modified.output[1].value = confidential::Value::Explicit(501),
            _ => modified.input[0].sequence = Sequence::ENABLE_RBF_NO_LOCKTIME,
        }
        assert!(
            bond().satisfy(&env_for(bond(), modified), &action).is_err(),
            "attack {attack}"
        );
    }
}

#[test]
fn penalty_still_works_after_deadline_if_collateral_remains_unspent() {
    let (a, b) = evidence();
    let mut tx = penalty_env().tx().clone();
    tx.lock_time = elements::LockTime::from_height(config().refund_height + 1).unwrap();
    bond()
        .satisfy(&env_for(bond(), tx), &penalty_action(&a, &b))
        .unwrap();
}

#[test]
fn malformed_config_and_principal_as_collateral_are_rejected() {
    for attack in 0..6 {
        let mut c = config();
        match attack {
            0 => c.collateral = 0,
            1 => c.refund_height = c.active_until,
            2 => c.refund_height = 500_000_000,
            3 => c.active_until = 0,
            4 => c.matcher = c.owner,
            _ => c.protected_output = elements::OutPoint::null(),
        }
        assert!(c.compile().is_err(), "attack {attack}");
    }
    assert!(bond()
        .penalty_transaction(config().protected_output)
        .is_err());
    assert!(bond()
        .penalty_transaction(elements::OutPoint::null())
        .is_err());
}

#[test]
fn certificates_are_only_requested_for_the_protected_output() {
    let mut tx = transfer(1);
    check_authorization_subject(config().protected_output, &tx).unwrap();
    tx.input[0].previous_output.vout += 1;
    assert!(check_authorization_subject(config().protected_output, &tx).is_err());
    let mut tx = transfer(1);
    tx.input.push(tx.input[0].clone());
    assert!(check_authorization_subject(config().protected_output, &tx).is_err());
    let mut tx = transfer(1);
    tx.input[0].is_pegin = true;
    assert!(check_authorization_subject(config().protected_output, &tx).is_err());
}
