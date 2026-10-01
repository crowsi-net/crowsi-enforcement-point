use serde::{Deserialize, Serialize};

use super::{ActionBindingV1, SignedDigestV1};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnforcementOutcome {
    Applied,
    Rejected,
    Failed,
    Partial,
}

impl EnforcementOutcome {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Rejected => "rejected",
            Self::Failed => "failed",
            Self::Partial => "partial",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcementReceiptV2 {
    pub schema: String,
    pub receipt_id: String,
    pub command_jti: String,
    pub command_digest: String,
    pub security_domain: String,
    pub deployment_id: String,
    pub incident_id: String,
    pub target_id: String,
    pub release_reservation_id: String,
    pub fence_epoch: u64,
    pub binding: ActionBindingV1,
    pub provider: String,
    pub outcome: EnforcementOutcome,
    pub authorization_consumed: bool,
    pub applied_at: String,
    pub expected_resource_version: String,
    pub resulting_resource_version: Option<String>,
    pub residual_exposures: Vec<String>,
    pub evidence_digest: String,
    pub signed: SignedDigestV1,
}
