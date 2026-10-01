mod support;

use crowsi_enforcement_point::{EnforcementOutcome, FaultMode, ResourceState};
use support::{APPLIED_AT, Fixture};

#[test]
fn timeout_after_apply_is_failed_and_never_reapplied() {
    let fixture = Fixture::new();
    fixture
        .provider
        .set_next_fault(FaultMode::TimeoutAfterApply);
    let lease = fixture.lease(1, "etag-4", 8, 9);
    let first = fixture
        .point
        .execute_at_for_test(&lease, APPLIED_AT)
        .unwrap();
    let replay = fixture
        .point
        .execute_at_for_test(&lease, APPLIED_AT)
        .unwrap();

    assert_eq!(first, replay);
    assert_eq!(first.outcome, EnforcementOutcome::Failed);
    assert_eq!(fixture.provider.invocation_count(), 1);
    assert_eq!(
        fixture
            .provider
            .snapshot("host://device-a/firewall")
            .unwrap()
            .state,
        ResourceState::Isolated
    );
}

#[test]
fn partial_application_is_signed_partial_with_residual_exposure() {
    let fixture = Fixture::new();
    fixture.provider.set_next_fault(FaultMode::PartialApply);
    let receipt = fixture
        .point
        .execute_at_for_test(&fixture.lease(1, "etag-4", 8, 9), APPLIED_AT)
        .unwrap();

    assert_eq!(receipt.outcome, EnforcementOutcome::Partial);
    assert!(!receipt.residual_exposures.is_empty());
    assert!(receipt.resulting_resource_version.is_some());
}

#[test]
fn missing_provider_is_failed_never_applied() {
    let fixture = Fixture::new();
    let mut lease = fixture.lease(1, "etag-4", 8, 9);
    lease.command.target_id = "host://missing/firewall".into();
    lease.command.binding.resource = lease.command.target_id.clone();
    lease.command = fixture.command_signer.sign(lease.command).unwrap();
    lease.command_digest = lease.command.payload_digest();
    let receipt = fixture
        .point
        .execute_at_for_test(&lease, APPLIED_AT)
        .unwrap();
    assert_eq!(receipt.outcome, EnforcementOutcome::Failed);
}
