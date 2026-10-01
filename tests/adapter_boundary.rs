mod support;

use std::sync::Arc;

use crowsi_enforcement_point::{
    AdapterOutcome, AdapterStatus, EnforcementAdapter, EnforcementOutcome, EnforcementPoint,
    PepLedger, ProviderRequest, ResourceState, TrustedCommandKey, TrustedReceiptKey,
};
use support::{APPLIED_AT, Fixture};

struct HostileAdapter(AdapterOutcome);

impl EnforcementAdapter for HostileAdapter {
    fn apply(&self, _: &ProviderRequest) -> AdapterOutcome {
        self.0.clone()
    }
}

#[test]
fn inconsistent_adapter_success_is_never_signed_as_applied() {
    for outcome in invalid_successes() {
        let fixture = Fixture::new();
        let trusted = TrustedCommandKey::new(
            "command.fixture.1",
            fixture.command_signer.verifying_key(),
            "customer-sample",
            "deployment.sample.1",
        )
        .unwrap();
        let point = EnforcementPoint::new(
            PepLedger::open_in_memory().unwrap(),
            Arc::new(HostileAdapter(outcome)),
            trusted,
            fixture.receipt_signer.clone(),
            TrustedReceiptKey::new("receipt.fixture.1", fixture.receipt_signer.verifying_key())
                .unwrap(),
        )
        .unwrap();
        let receipt = point
            .execute_at_for_test(&fixture.lease(1, "etag-4", 8, 9), APPLIED_AT)
            .unwrap();
        assert_eq!(receipt.outcome, EnforcementOutcome::Failed);
        assert_eq!(
            receipt.residual_exposures,
            ["invalid-adapter-outcome".to_string()]
        );
    }
}

fn invalid_successes() -> Vec<AdapterOutcome> {
    vec![
        applied(false, Some(9), Some(ResourceState::Isolated)),
        applied(true, Some(8), Some(ResourceState::Isolated)),
        applied(true, Some(9), Some(ResourceState::Connected)),
        applied(true, Some(9), None),
    ]
}

fn applied(
    changed_state: bool,
    fence: Option<u64>,
    state: Option<ResourceState>,
) -> AdapterOutcome {
    AdapterOutcome {
        status: AdapterStatus::Applied,
        reason_code: "applied".into(),
        changed_state,
        resource_version: Some("etag-5".into()),
        fence,
        state,
    }
}
