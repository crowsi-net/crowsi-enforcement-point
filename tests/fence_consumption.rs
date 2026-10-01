mod support;

use std::sync::Arc;

use crowsi_enforcement_point::{
    EnforcementOutcome, EnforcementPoint, PepLedger, SqliteProvider, TrustedCommandKey,
    TrustedReceiptKey,
};
use support::{APPLIED_AT, Fixture, resource};

#[test]
fn greater_fence_is_consumed_before_a_known_version_rejection() {
    let fixture = Fixture::new();
    let mismatch = fixture.lease(1, "etag-stale", 8, 9);
    let rejected = fixture
        .point
        .execute_at_for_test(&mismatch, APPLIED_AT)
        .unwrap();
    let snapshot = fixture
        .provider
        .snapshot("host://device-a/firewall")
        .unwrap();

    assert_eq!(rejected.outcome, EnforcementOutcome::Rejected);
    assert_eq!(snapshot.resource_version, "etag-4");
    assert_eq!(snapshot.latest_fence, 9);
    let old = fixture.lease(2, "etag-4", 8, 9);
    let stale = fixture.point.execute_at_for_test(&old, APPLIED_AT).unwrap();
    assert_eq!(stale.outcome, EnforcementOutcome::Rejected);
    assert!(stale.residual_exposures.contains(&"stale-fence".into()));
}

#[test]
fn sqlite_provider_keeps_the_consumed_fence_across_restart() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("provider.sqlite3");
    let provider = Arc::new(SqliteProvider::open_for_test(&path).unwrap());
    provider.register(&resource()).unwrap();
    let fixture = Fixture::new();
    let receipt_signer = fixture.receipt_signer.clone();
    let trusted = TrustedCommandKey::new(
        "command.fixture.1",
        fixture.command_signer.verifying_key(),
        "customer-sample",
        "deployment.sample.1",
    )
    .unwrap();
    let receipt_key =
        TrustedReceiptKey::new("receipt.fixture.1", receipt_signer.verifying_key()).unwrap();
    let mismatch = fixture.lease(3, "etag-stale", 8, 9);
    let point = EnforcementPoint::new(
        PepLedger::open_in_memory().unwrap(),
        provider.clone(),
        trusted.clone(),
        receipt_signer.clone(),
        receipt_key.clone(),
    )
    .unwrap();
    assert_eq!(
        point
            .execute_at_for_test(&mismatch, APPLIED_AT)
            .unwrap()
            .outcome,
        EnforcementOutcome::Rejected
    );
    drop(point);
    drop(provider);

    let reopened = Arc::new(SqliteProvider::open_for_test(&path).unwrap());
    assert_eq!(
        reopened
            .snapshot("host://device-a/firewall")
            .unwrap()
            .unwrap()
            .latest_fence,
        9
    );
    let old = fixture.lease(4, "etag-4", 8, 9);
    let point = EnforcementPoint::new(
        PepLedger::open_in_memory().unwrap(),
        reopened,
        trusted,
        receipt_signer,
        receipt_key,
    )
    .unwrap();
    let stale = point.execute_at_for_test(&old, APPLIED_AT).unwrap();
    assert_eq!(stale.outcome, EnforcementOutcome::Rejected);
    assert!(stale.residual_exposures.contains(&"stale-fence".into()));
}
