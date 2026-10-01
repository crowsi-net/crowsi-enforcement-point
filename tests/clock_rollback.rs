mod support;

use std::sync::Arc;

use crowsi_enforcement_point::{
    EnforcementPoint, MemoryProvider, PepError, PepLedger, TrustedCommandKey, TrustedReceiptKey,
};
use support::{APPLIED_AT, Fixture, resource};

#[test]
fn durable_time_watermark_rejects_rollback_after_restart() {
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
    let receipt_key =
        TrustedReceiptKey::new("receipt.fixture.1", fixture.receipt_signer.verifying_key())
            .unwrap();
    let point = EnforcementPoint::new(
        PepLedger::open_for_test(&path).unwrap(),
        provider.clone(),
        trusted.clone(),
        fixture.receipt_signer.clone(),
        receipt_key.clone(),
    )
    .unwrap();
    let lease = fixture.lease(7, "etag-4", 8, 9);
    point.execute_at_for_test(&lease, APPLIED_AT).unwrap();
    drop(point);

    let restarted = EnforcementPoint::new(
        PepLedger::open_for_test(&path).unwrap(),
        provider.clone(),
        trusted,
        fixture.receipt_signer,
        receipt_key,
    )
    .unwrap();
    assert!(matches!(
        restarted.execute_at_for_test(&lease, "2026-07-29T00:01:59.000Z"),
        Err(PepError::ClockRollback)
    ));
    assert_eq!(provider.invocation_count(), 1);
}
