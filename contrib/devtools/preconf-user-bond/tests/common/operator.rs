use super::*;
use elementsplus_preconf::operator::{Bond, Config, Receipt};

pub fn config() -> Config {
    let c = super::config();
    Config {
        genesis: c.genesis,
        fee_asset: c.fee_asset,
        preconfer: c.matcher,
        protected_output: c.protected_output,
        epoch: c.epoch,
        collateral: c.collateral,
        active_until: c.active_until,
        refund_height: c.refund_height,
    }
}
pub fn bond() -> &'static Bond {
    static BOND: OnceLock<Bond> = OnceLock::new();
    BOND.get_or_init(|| config().compile().expect("operator contract compiles"))
}
pub fn receipt(output: OutPoint, txid: Txid) -> Receipt {
    Receipt {
        bond: output,
        txid,
        signature: sign(bond().digest(output, txid), 2),
    }
}
pub fn evidence() -> (Receipt, Receipt) {
    (
        receipt(collateral(), transfer(1).txid()),
        receipt(collateral(), transfer(2).txid()),
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
