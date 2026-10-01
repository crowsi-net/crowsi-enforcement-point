#[test]
fn sample_emits_only_v2_lease_and_signed_v2_receipts() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_crowsi-enforcement-point"))
        .arg("sample")
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema"], "crowsi.pep-v2-conformance-sample");
    assert_eq!(value["external_actions"], false);
    assert_eq!(
        value["scenarios"][0]["lease"]["schema"],
        "crowsi://control/pep-execution-lease/v2"
    );
    assert_eq!(
        value["scenarios"][0]["receipt"]["schema"],
        "crowsi://control/enforcement-receipt/v2"
    );
    assert_eq!(value["scenarios"][0]["receipt"]["outcome"], "applied");
    assert_eq!(value["scenarios"][1]["receipt"]["outcome"], "failed");
    assert_eq!(value["scenarios"][2]["receipt"]["outcome"], "partial");
}
