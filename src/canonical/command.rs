use crate::IsolationCommandV2;

use super::{CanonicalV2, Encoder, binding};

impl CanonicalV2 for IsolationCommandV2 {
    fn payload(&self) -> Vec<u8> {
        let mut value = Encoder::new("isolation-command-v2");
        value.text("schema", &self.schema);
        value.text("command_id", &self.command_id);
        value.text("jti", &self.jti);
        value.text("security_domain", &self.security_domain);
        value.text("deployment_id", &self.deployment_id);
        value.text("incident_id", &self.incident_id);
        value.text("target_id", &self.target_id);
        value.text("release_id", &self.release_id);
        value.text("release_digest", &self.release_digest);
        value.text("checkpoint_id", &self.checkpoint_id);
        value.text("checkpoint_digest", &self.checkpoint_digest);
        value.number("checkpoint_sequence", self.checkpoint_sequence);
        value.text("release_reservation_id", &self.release_reservation_id);
        value.text("enforcement_grant_jti", &self.enforcement_grant_jti);
        value.text("decision_id", &self.decision_id);
        value.text("pairwise_subject", &self.pairwise_subject);
        value.text("actor", &self.actor);
        value.text("device", &self.device);
        value.text("workload", &self.workload);
        value.text("profile", &self.profile);
        value.text("proof_key_ref", &self.proof_key_ref);
        value.number("revocation_epoch", self.revocation_epoch);
        binding(&mut value, &self.binding);
        value.text("provider", &self.provider);
        value.number("previous_fence_epoch", self.previous_fence_epoch);
        value.number("fence_epoch", self.fence_epoch);
        value.text("expected_resource_version", &self.expected_resource_version);
        value.text("issued_at", &self.issued_at);
        value.text("expires_at", &self.expires_at);
        value.finish()
    }
}
