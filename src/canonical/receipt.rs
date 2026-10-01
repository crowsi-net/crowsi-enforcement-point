use crate::EnforcementReceiptV2;

use super::{CanonicalV2, Encoder, binding};

impl CanonicalV2 for EnforcementReceiptV2 {
    fn payload(&self) -> Vec<u8> {
        let mut value = Encoder::new("enforcement-receipt-v2");
        value.text("schema", &self.schema);
        value.text("receipt_id", &self.receipt_id);
        value.text("command_jti", &self.command_jti);
        value.text("command_digest", &self.command_digest);
        value.text("security_domain", &self.security_domain);
        value.text("deployment_id", &self.deployment_id);
        value.text("incident_id", &self.incident_id);
        value.text("target_id", &self.target_id);
        value.text("release_reservation_id", &self.release_reservation_id);
        value.number("fence_epoch", self.fence_epoch);
        binding(&mut value, &self.binding);
        value.text("provider", &self.provider);
        value.text("outcome", self.outcome.code());
        value.boolean("authorization_consumed", self.authorization_consumed);
        value.text("applied_at", &self.applied_at);
        value.text("expected_resource_version", &self.expected_resource_version);
        value.optional_text(
            "resulting_resource_version",
            self.resulting_resource_version.as_deref(),
        );
        value.strings("residual_exposures", &self.residual_exposures);
        value.text("evidence_digest", &self.evidence_digest);
        value.finish()
    }
}
