use crate::{AdapterOutcome, AdapterStatus, ControlAction, ProviderRequest, ResourceState};

pub(super) fn normalize(request: &ProviderRequest, value: AdapterOutcome) -> AdapterOutcome {
    if valid_text(&value.reason_code)
        && value.resource_version.as_deref().is_none_or(valid_text)
        && valid_shape(request, &value)
    {
        value
    } else {
        AdapterOutcome::unknown("invalid-adapter-outcome")
    }
}

fn valid_shape(request: &ProviderRequest, value: &AdapterOutcome) -> bool {
    match value.status {
        AdapterStatus::Applied => {
            value.changed_state
                && value.resource_version.is_some()
                && value.fence == Some(request.fence)
                && value.state == Some(desired(request.action))
        }
        AdapterStatus::Partial => {
            value.changed_state
                && value.resource_version.is_some()
                && value.fence == Some(request.fence)
                && value.state == Some(ResourceState::Indeterminate)
        }
        AdapterStatus::Timeout => {
            if value.changed_state {
                value.resource_version.is_some()
                    && value.fence == Some(request.fence)
                    && value.state.is_some()
            } else {
                no_result(value)
            }
        }
        AdapterStatus::Rejected => {
            !value.changed_state
                && (no_result(value)
                    || value.resource_version.is_some()
                        && value.fence.is_some_and(|fence| fence >= request.fence)
                        && value.state.is_some())
        }
        AdapterStatus::Unknown => !value.changed_state,
    }
}

fn no_result(value: &AdapterOutcome) -> bool {
    value.resource_version.is_none() && value.fence.is_none() && value.state.is_none()
}

fn valid_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

const fn desired(action: ControlAction) -> ResourceState {
    match action {
        ControlAction::Quarantine | ControlAction::RestrictEgress => ResourceState::Isolated,
        ControlAction::RevokeAccess => ResourceState::Revoked,
        ControlAction::Restore => ResourceState::Connected,
    }
}
