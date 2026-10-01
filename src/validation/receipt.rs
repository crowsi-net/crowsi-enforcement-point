use crate::{EnforcementOutcome, EnforcementReceiptV2, Result, canonical};

use super::{common, digest, identifier, opaque};

pub(crate) fn validate(value: &EnforcementReceiptV2) -> Result<()> {
    if value.schema != "crowsi://control/enforcement-receipt/v2" {
        return common::invalid("receipt.schema");
    }
    for (field, entry) in [
        ("receipt_id", value.receipt_id.as_str()),
        ("command_jti", &value.command_jti),
        ("security_domain", &value.security_domain),
        ("deployment_id", &value.deployment_id),
        ("incident_id", &value.incident_id),
        ("release_reservation_id", &value.release_reservation_id),
        ("provider", &value.provider),
    ] {
        identifier(field, entry)?;
    }
    digest("command_digest", &value.command_digest)?;
    opaque("target_id", &value.target_id)?;
    opaque(
        "expected_resource_version",
        &value.expected_resource_version,
    )?;
    identifier("binding.audience", &value.binding.audience)?;
    opaque("binding.resource", &value.binding.resource)?;
    identifier("binding.purpose", &value.binding.purpose)?;
    if value.fence_epoch == 0
        || value.target_id != value.binding.resource
        || value.provider != value.binding.audience
        || !value.authorization_consumed
    {
        return common::invalid("receipt.binding");
    }
    super::timestamp(&value.applied_at)?;
    outcome(value)?;
    digest("evidence_digest", &value.evidence_digest)?;
    identifier("signed.key_id", &value.signed.key_id)?;
    digest("signed.digest", &value.signed.digest)?;
    common::signature(&value.signed.signature)?;
    if value.signed.digest != canonical::digest(value) {
        return common::invalid("receipt.signed.digest");
    }
    Ok(())
}

fn outcome(value: &EnforcementReceiptV2) -> Result<()> {
    if value.residual_exposures.len() > 32 {
        return common::invalid("receipt.residual_exposures");
    }
    for exposure in &value.residual_exposures {
        opaque("receipt.residual_exposures", exposure)?;
    }
    if let Some(version) = value.resulting_resource_version.as_deref() {
        opaque("resulting_resource_version", version)?;
    }
    if value.outcome == EnforcementOutcome::Partial && value.residual_exposures.is_empty() {
        return common::invalid("partial residual exposure");
    }
    if value.outcome == EnforcementOutcome::Applied
        && (value.resulting_resource_version.is_none() || !value.residual_exposures.is_empty())
    {
        return common::invalid("applied outcome");
    }
    Ok(())
}
