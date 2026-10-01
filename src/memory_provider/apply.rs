use crate::{
    AdapterOutcome, AdapterStatus, ControlAction, EnforcementAdapter, ProviderRequest,
    ResourceState,
};

use super::{FaultMode, MemoryProvider};

impl EnforcementAdapter for MemoryProvider {
    fn apply(&self, request: &ProviderRequest) -> AdapterOutcome {
        let mut store = self.lock();
        store.invocations = store.invocations.saturating_add(1);
        if let Some((digest, result)) = store.outcomes.get(&request.command_jti) {
            return if digest == &request.command_digest {
                result.clone()
            } else {
                rejected("provider-idempotency-conflict")
            };
        }
        let fault = std::mem::take(&mut store.next_fault);
        if matches!(
            fault,
            FaultMode::Unavailable | FaultMode::TimeoutBeforeApply
        ) {
            let result = if fault == FaultMode::Unavailable {
                AdapterOutcome::unknown("provider-unreachable")
            } else {
                timeout()
            };
            remember(&mut store, request, &result);
            return result;
        }
        let Some(resource) = store.resources.get_mut(&request.resource_uri) else {
            let result = AdapterOutcome::unknown("provider-unreachable");
            remember(&mut store, request, &result);
            return result;
        };
        if let Some(result) = binding_rejection(resource, request) {
            remember(&mut store, request, &result);
            return result;
        }
        if request.fence <= resource.latest_fence {
            let result = rejected_with(resource, "stale-fence");
            remember(&mut store, request, &result);
            return result;
        }
        resource.latest_fence = request.fence;
        if request.expected_resource_version != resource.resource_version {
            let result = rejected_with(resource, "resource-version-conflict");
            remember(&mut store, request, &result);
            return result;
        }
        resource.resource_version = resulting_version(request);
        resource.latest_fence = request.fence;
        resource.state = match fault {
            FaultMode::PartialApply => ResourceState::Indeterminate,
            _ => desired_state(request.action),
        };
        let result = outcome(resource, fault);
        remember(&mut store, request, &result);
        result
    }
}

fn binding_rejection(
    resource: &crate::ResourceRecord,
    request: &ProviderRequest,
) -> Option<AdapterOutcome> {
    if resource.security_domain != request.security_domain
        || resource.deployment_id != request.deployment_id
        || resource.provider != request.provider
    {
        Some(rejected("provider-binding-mismatch"))
    } else {
        None
    }
}

fn outcome(resource: &crate::ResourceRecord, fault: FaultMode) -> AdapterOutcome {
    let (status, reason) = match fault {
        FaultMode::TimeoutAfterApply => (AdapterStatus::Timeout, "provider-timeout"),
        FaultMode::PartialApply => (AdapterStatus::Partial, "partial-application"),
        _ => (AdapterStatus::Applied, "applied"),
    };
    AdapterOutcome {
        status,
        reason_code: reason.into(),
        changed_state: true,
        resource_version: Some(resource.resource_version.clone()),
        fence: Some(resource.latest_fence),
        state: Some(resource.state),
    }
}

fn desired_state(action: ControlAction) -> ResourceState {
    match action {
        ControlAction::Quarantine | ControlAction::RestrictEgress => ResourceState::Isolated,
        ControlAction::RevokeAccess => ResourceState::Revoked,
        ControlAction::Restore => ResourceState::Connected,
    }
}

fn remember(
    store: &mut super::state::ProviderState,
    request: &ProviderRequest,
    result: &AdapterOutcome,
) {
    store.outcomes.insert(
        request.command_jti.clone(),
        (request.command_digest.clone(), result.clone()),
    );
}

fn rejected(reason: &str) -> AdapterOutcome {
    AdapterOutcome {
        status: AdapterStatus::Rejected,
        reason_code: reason.into(),
        changed_state: false,
        resource_version: None,
        fence: None,
        state: None,
    }
}

fn rejected_with(resource: &crate::ResourceRecord, reason: &str) -> AdapterOutcome {
    AdapterOutcome {
        status: AdapterStatus::Rejected,
        reason_code: reason.into(),
        changed_state: false,
        resource_version: Some(resource.resource_version.clone()),
        fence: Some(resource.latest_fence),
        state: Some(resource.state),
    }
}

fn resulting_version(request: &ProviderRequest) -> String {
    format!("rv:{}:{}", request.provider, request.fence)
}

fn timeout() -> AdapterOutcome {
    AdapterOutcome {
        status: AdapterStatus::Timeout,
        reason_code: "provider-timeout".into(),
        changed_state: false,
        resource_version: None,
        fence: None,
        state: None,
    }
}
