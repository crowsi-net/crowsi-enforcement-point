mod support;

use std::sync::Arc;

use crowsi_enforcement_point::{
    EnforcementPoint, MemoryProvider, PepError, PepLedger, TrustedCommandKey, TrustedReceiptKey,
};
use rusqlite::{Connection, params};
use support::{APPLIED_AT, Fixture, TestCommandSigner, resource};

#[test]
fn forged_expired_or_lease_mismatched_commands_never_reach_provider() {
    let fixture = Fixture::new();
    let attacker = TestCommandSigner::from_seed("command.fixture.1", [99; 32]);
    let mut forged = fixture.lease(1, "etag-4", 8, 9);
    forged.command = attacker.sign(forged.command).unwrap();
    forged.command_digest = forged.command.payload_digest();
    assert!(matches!(
        fixture.point.execute_at_for_test(&forged, APPLIED_AT),
        Err(PepError::Signature)
    ));

    let mut expired = fixture.lease(2, "etag-4", 8, 9);
    expired.command.expires_at = APPLIED_AT.into();
    expired.command = fixture.command_signer.sign(expired.command).unwrap();
    expired.command_digest = expired.command.payload_digest();
    assert!(matches!(
        fixture.point.execute_at_for_test(&expired, APPLIED_AT),
        Err(PepError::TimeWindow)
    ));

    let mut mismatch = fixture.lease(3, "etag-4", 8, 9);
    mismatch.reservation_id = "release-reservation.other".into();
    assert!(matches!(
        fixture.point.execute_at_for_test(&mismatch, APPLIED_AT),
        Err(PepError::Validation(_))
    ));
    assert_eq!(fixture.provider.invocation_count(), 0);
}

#[test]
fn restore_remains_bound_to_the_signed_recovery_path() {
    let fixture = Fixture::new();
    let mut lease = fixture.lease(1, "etag-4", 8, 9);
    lease.command.binding.action = crowsi_enforcement_point::ControlAction::Restore;
    lease.command.binding.channel = crowsi_enforcement_point::ControlChannel::ServiceAutomation;
    lease.command = fixture.command_signer.sign(lease.command).unwrap();
    lease.command_digest = lease.command.payload_digest();
    assert!(matches!(
        fixture.point.execute_at_for_test(&lease, APPLIED_AT),
        Err(PepError::Validation(_))
    ));
}

#[test]
fn corrupted_durable_replay_receipt_fails_closed() {
    let fixture = Fixture::new();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("pep.sqlite3");
    let provider = Arc::new(MemoryProvider::new());
    provider.register(resource()).unwrap();
    let trusted = TrustedCommandKey::new(
        "command.fixture.1",
        fixture.command_signer.verifying_key(),
        "customer-sample",
        "deployment.sample.1",
    )
    .unwrap();
    let point = EnforcementPoint::new(
        PepLedger::open_for_test(&path).unwrap(),
        provider.clone(),
        trusted.clone(),
        fixture.receipt_signer.clone(),
        TrustedReceiptKey::new("receipt.fixture.1", fixture.receipt_signer.verifying_key())
            .unwrap(),
    )
    .unwrap();
    let lease = fixture.lease(9, "etag-4", 8, 9);
    point.execute_at_for_test(&lease, APPLIED_AT).unwrap();
    drop(point);

    let connection = Connection::open(&path).unwrap();
    let encoded: String = connection
        .query_row("SELECT receipt_json FROM enforcement_attempts", [], |row| {
            row.get(0)
        })
        .unwrap();
    let mut receipt: serde_json::Value = serde_json::from_str(&encoded).unwrap();
    receipt["signed"]["signature"] = serde_json::Value::String("a".repeat(86));
    connection
        .execute(
            "UPDATE enforcement_attempts SET receipt_json = ?1",
            params![serde_json::to_string(&receipt).unwrap()],
        )
        .unwrap();
    drop(connection);

    let point = EnforcementPoint::new(
        PepLedger::open_for_test(&path).unwrap(),
        provider.clone(),
        trusted,
        fixture.receipt_signer.clone(),
        TrustedReceiptKey::new("receipt.fixture.1", fixture.receipt_signer.verifying_key())
            .unwrap(),
    )
    .unwrap();
    assert!(point.execute_at_for_test(&lease, APPLIED_AT).is_err());
    assert_eq!(provider.invocation_count(), 1);
}
