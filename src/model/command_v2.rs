use serde::{Deserialize, Serialize};

use super::{ActionBindingV1, SignedDigestV1};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IsolationCommandV2 {
    pub schema: String,
    pub command_id: String,
    pub jti: String,
    pub security_domain: String,
    pub deployment_id: String,
    pub incident_id: String,
    pub target_id: String,
    pub release_id: String,
    pub release_digest: String,
    pub checkpoint_id: String,
    pub checkpoint_digest: String,
    pub checkpoint_sequence: u64,
    pub release_reservation_id: String,
    pub enforcement_grant_jti: String,
    pub decision_id: String,
    pub pairwise_subject: String,
    pub actor: String,
    pub device: String,
    pub workload: String,
    pub profile: String,
    pub proof_key_ref: String,
    pub revocation_epoch: u64,
    pub binding: ActionBindingV1,
    pub provider: String,
    pub previous_fence_epoch: u64,
    pub fence_epoch: u64,
    pub expected_resource_version: String,
    pub issued_at: String,
    pub expires_at: String,
    pub signed: SignedDigestV1,
}
