use crate::{IsolationCommandV2, PepExecutionLeaseV2, Result, canonical};

use super::{common, digest, identifier, opaque};

pub(crate) fn validate(value: &IsolationCommandV2) -> Result<()> {
    if value.schema != "crowsi://control/isolation-command/v2" {
        return common::invalid("command.schema");
    }
    for (field, entry) in identifiers(value) {
        identifier(field, entry)?;
    }
    for (field, entry) in opaques(value) {
        opaque(field, entry)?;
    }
    super::workload::spiffe(&value.workload)?;
    digest("release_digest", &value.release_digest)?;
    digest("checkpoint_digest", &value.checkpoint_digest)?;
    identifier("binding.audience", &value.binding.audience)?;
    opaque("binding.resource", &value.binding.resource)?;
    identifier("binding.purpose", &value.binding.purpose)?;
    if value.target_id != value.binding.resource
        || value.provider != value.binding.audience
        || value.checkpoint_sequence == 0
        || value.fence_epoch == 0
        || value.previous_fence_epoch.checked_add(1) != Some(value.fence_epoch)
    {
        return common::invalid("command.cas-binding");
    }
    super::time::short_window(&value.issued_at, &value.expires_at)?;
    signed(value)?;
    if value.signed.digest != canonical::digest(value) {
        return common::invalid("command.signed.digest");
    }
    Ok(())
}

pub(crate) fn lease(value: &PepExecutionLeaseV2) -> Result<()> {
    if value.schema != "crowsi://control/pep-execution-lease/v2" {
        return common::invalid("lease.schema");
    }
    identifier("reservation_id", &value.reservation_id)?;
    digest("command_digest", &value.command_digest)?;
    super::timestamp(&value.reserved_at)?;
    validate(&value.command)?;
    if value.reservation_id != value.command.release_reservation_id
        || value.command_digest != value.command.payload_digest()
        || !super::in_window(
            &value.command.issued_at,
            &value.reserved_at,
            &value.command.expires_at,
        )?
    {
        return common::invalid("lease.binding");
    }
    Ok(())
}

fn signed(value: &IsolationCommandV2) -> Result<()> {
    identifier("signed.key_id", &value.signed.key_id)?;
    digest("signed.digest", &value.signed.digest)?;
    common::signature(&value.signed.signature)
}

fn identifiers(value: &IsolationCommandV2) -> [(&'static str, &str); 11] {
    [
        ("command_id", &value.command_id),
        ("jti", &value.jti),
        ("security_domain", &value.security_domain),
        ("deployment_id", &value.deployment_id),
        ("incident_id", &value.incident_id),
        ("release_id", &value.release_id),
        ("checkpoint_id", &value.checkpoint_id),
        ("release_reservation_id", &value.release_reservation_id),
        ("enforcement_grant_jti", &value.enforcement_grant_jti),
        ("decision_id", &value.decision_id),
        ("provider", &value.provider),
    ]
}

fn opaques(value: &IsolationCommandV2) -> [(&'static str, &str); 7] {
    [
        ("target_id", &value.target_id),
        ("pairwise_subject", &value.pairwise_subject),
        ("actor", &value.actor),
        ("device", &value.device),
        ("profile", &value.profile),
        ("proof_key_ref", &value.proof_key_ref),
        (
            "expected_resource_version",
            &value.expected_resource_version,
        ),
    ]
}
