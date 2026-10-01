use serde::{Deserialize, Serialize};

use super::{ActionBindingV1, ControlAction};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    Host,
    HostFirewall,
    CloudProvider,
    Incus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceState {
    Connected,
    Isolated,
    Revoked,
    Indeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    pub security_domain: String,
    pub deployment_id: String,
    pub resource_uri: String,
    pub provider: String,
    pub kind: ProviderKind,
    pub resource_version: String,
    pub latest_fence: u64,
    pub state: ResourceState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderRequest {
    pub command_id: String,
    pub command_jti: String,
    pub command_digest: String,
    pub release_reservation_id: String,
    pub security_domain: String,
    pub deployment_id: String,
    pub incident_id: String,
    pub resource_uri: String,
    pub provider: String,
    pub action: ControlAction,
    pub binding: ActionBindingV1,
    pub expected_resource_version: String,
    pub previous_fence: u64,
    pub fence: u64,
    pub release_digest: String,
    pub checkpoint_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdapterStatus {
    Applied,
    Rejected,
    Partial,
    Timeout,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterOutcome {
    pub status: AdapterStatus,
    pub reason_code: String,
    pub changed_state: bool,
    pub resource_version: Option<String>,
    pub fence: Option<u64>,
    pub state: Option<ResourceState>,
}

impl AdapterOutcome {
    pub(crate) fn unknown(reason: &str) -> Self {
        Self {
            status: AdapterStatus::Unknown,
            reason_code: reason.into(),
            changed_state: false,
            resource_version: None,
            fence: None,
            state: None,
        }
    }
}

impl ResourceState {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Isolated => "isolated",
            Self::Revoked => "revoked",
            Self::Indeterminate => "indeterminate",
        }
    }
}
