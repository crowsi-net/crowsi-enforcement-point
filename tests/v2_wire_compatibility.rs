mod support;

use crowsi_enforcement_point::{
    EnforcementOutcome, EnforcementReceiptV2, PepExecutionLeaseV2, TrustedReceiptKey,
};
use support::{APPLIED_AT, Fixture};

#[test]
fn released_control_contract_fixture_has_the_exact_v2_shape() {
    let lease: PepExecutionLeaseV2 = serde_json::from_str(include_str!(
        "../fixtures/pep-execution-lease-v2.sample.json"
    ))
    .unwrap();
    lease.validate_contract().unwrap();
    assert_eq!(lease.schema, "crowsi://control/pep-execution-lease/v2");
    assert_eq!(
        lease.command.schema,
        "crowsi://control/isolation-command/v2"
    );
    assert_eq!(lease.command_digest, lease.command.payload_digest());
}

#[test]
fn released_receipt_fixture_uses_the_same_canonical_digest() {
    let receipt: EnforcementReceiptV2 = serde_json::from_str(include_str!(
        "../fixtures/enforcement-receipt-v2.sample.json"
    ))
    .unwrap();
    receipt.validate_contract().unwrap();
    assert_eq!(
        receipt.signed.digest,
        "sha256:6789ed811dbe127350a4de89f4765eedb396c1b7779ddb5f46f55d4c7f47c680"
    );
}

#[test]
fn pa_fixture_flows_through_pep_to_a_signed_v2_receipt() {
    let fixture = Fixture::new();
    let lease = fixture.lease(42, "etag-4", 8, 9);
    let receipt = fixture
        .point
        .execute_at_for_test(&lease, APPLIED_AT)
        .unwrap();
    let encoded = serde_json::to_vec(&receipt).unwrap();
    let decoded: EnforcementReceiptV2 = serde_json::from_slice(&encoded).unwrap();
    let verifier =
        TrustedReceiptKey::new("receipt.fixture.1", fixture.receipt_signer.verifying_key())
            .unwrap();

    decoded.validate_contract().unwrap();
    verifier.verify(&decoded).unwrap();
    assert_eq!(decoded.outcome, EnforcementOutcome::Applied);
    assert_eq!(decoded.command_jti, lease.command.jti);
    assert_eq!(decoded.command_digest, lease.command_digest);
    assert_eq!(decoded.fence_epoch, lease.command.fence_epoch);
    assert_eq!(decoded.binding, lease.command.binding);
}

#[test]
fn released_wire_rejects_non_spiffe_workload_even_with_matching_digest() {
    let fixture = Fixture::new();
    let mut lease = fixture.lease(42, "etag-4", 8, 9);
    lease.command.workload = "rescue-console-sample".into();
    lease.command.signed.digest = lease.command.payload_digest();
    lease
        .command_digest
        .clone_from(&lease.command.signed.digest);
    assert!(lease.validate_contract().is_err());
}

#[test]
fn all_published_pep_wire_schemas_are_closed_v2_contracts() {
    for (source, id) in [
        (
            include_str!("../schemas/isolation-command-v2.schema.json"),
            "crowsi://control/isolation-command/v2",
        ),
        (
            include_str!("../schemas/pep-execution-lease-v2.schema.json"),
            "crowsi://control/pep-execution-lease/v2",
        ),
        (
            include_str!("../schemas/enforcement-receipt-v2.schema.json"),
            "crowsi://control/enforcement-receipt/v2",
        ),
        (
            include_str!("../schemas/pep-receipt-trust-manifest-v1.schema.json"),
            "crowsi://enforcement-point/pep-receipt-trust-manifest/v1",
        ),
    ] {
        let schema: serde_json::Value = serde_json::from_str(source).unwrap();
        assert_eq!(schema["$id"], id);
        assert_eq!(schema["additionalProperties"], false);
    }
}
