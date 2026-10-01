use crate::{AdapterOutcome, AdapterStatus, ProviderRequest, ResourceRecord};

pub(crate) fn binding(
    resource: &ResourceRecord,
    request: &ProviderRequest,
) -> Option<AdapterOutcome> {
    let mismatch = resource.security_domain != request.security_domain
        || resource.deployment_id != request.deployment_id
        || resource.provider != request.provider;
    mismatch.then(|| rejected("provider-binding-mismatch"))
}

pub(crate) fn stale(resource: &ResourceRecord, request: &ProviderRequest) -> bool {
    request.fence <= resource.latest_fence
}

pub(crate) fn rejected(reason: &str) -> AdapterOutcome {
    AdapterOutcome {
        status: AdapterStatus::Rejected,
        reason_code: reason.into(),
        changed_state: false,
        resource_version: None,
        fence: None,
        state: None,
    }
}

pub(crate) fn rejected_after_fence(
    reason: &str,
    resource: &ResourceRecord,
    fence: u64,
) -> AdapterOutcome {
    AdapterOutcome {
        status: AdapterStatus::Rejected,
        reason_code: reason.into(),
        changed_state: false,
        resource_version: Some(resource.resource_version.clone()),
        fence: Some(fence),
        state: Some(resource.state),
    }
}
