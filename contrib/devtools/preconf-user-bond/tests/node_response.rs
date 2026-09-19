// Test only the CLI response boundary; transaction validity is tested by check-node.py.
#![cfg(unix)]
mod common;
use elementsplus_preconf::check_authorized_transaction;
use serde_json::json;
use std::process::Command;

#[test]
fn node_response_must_affirm_exact_transaction() {
    let tx = common::transfer(1);
    let expected = json!([{"allowed": true, "txid": tx.txid().to_string()}]).to_string();
    let check = |response: &str, exit: &str| {
        let mut cli = Command::new("sh");
        cli.args(["-c", "printf '%s' \"$RESPONSE\"; exit \"$STATUS\""])
            .env("RESPONSE", response)
            .env("STATUS", exit);
        check_authorized_transaction(common::config().protected_output, &tx, cli)
    };
    assert_eq!(check(&expected, "0").unwrap(), tx.txid());
    for response in [
        "",
        "{}",
        "[]",
        "[{}]",
        "null",
        "[{'allowed':true}]",
        r#"[{"allowed":true,"txid":"wrong"}]"#,
        r#"[{"allowed":false}]"#,
        r#"[{"allowed":"true"}]"#,
    ] {
        assert!(check(response, "0").is_err(), "{response}");
    }
    assert!(check(&expected, "1").is_err());
    assert!(check_authorized_transaction(
        common::config().protected_output,
        &tx,
        Command::new("/nonexistent/preconf-test-cli")
    )
    .is_err());
}
