use sha2::{Digest, Sha256};

use crate::{
    AdapterOutcome, AdapterStatus, EnforcementOutcome, EnforcementReceiptV2, PepError,
    PepExecutionLeaseV2, Result, SignatureAlgorithm, SignedDigestV1,
};

pub(super) fn create(
    lease: &PepExecutionLeaseV2,
    applied_at: &str,
    adapter: &AdapterOutcome,
) -> Result<EnforcementReceiptV2> {
    let command = &lease.command;
    let outcome = outcome(adapter.status);
    let residual_exposures = if outcome == EnforcementOutcome::Applied {
        Vec::new()
    } else {
        vec![adapter.reason_code.clone()]
    };
    Ok(EnforcementReceiptV2 {
        schema: "crowsi://control/enforcement-receipt/v2".into(),
        receipt_id: format!("receipt.{}", &lease.command_digest[7..39]),
        command_jti: command.jti.clone(),
        command_digest: lease.command_digest.clone(),
        security_domain: command.security_domain.clone(),
        deployment_id: command.deployment_id.clone(),
        incident_id: command.incident_id.clone(),
        target_id: command.target_id.clone(),
        release_reservation_id: lease.reservation_id.clone(),
        fence_epoch: command.fence_epoch,
        binding: command.binding.clone(),
        provider: command.provider.clone(),
        outcome,
        authorization_consumed: true,
        applied_at: applied_at.into(),
        expected_resource_version: command.expected_resource_version.clone(),
        resulting_resource_version: adapter.resource_version.clone(),
        residual_exposures,
        evidence_digest: evidence_digest(adapter)?,
        signed: unsigned(),
    })
}

pub(super) fn matches_lease(
    receipt: &EnforcementReceiptV2,
    lease: &PepExecutionLeaseV2,
) -> Result<()> {
    let command = &lease.command;
    let matches = receipt.command_jti == command.jti
        && receipt.command_digest == lease.command_digest
        && receipt.security_domain == command.security_domain
        && receipt.deployment_id == command.deployment_id
        && receipt.incident_id == command.incident_id
        && receipt.target_id == command.target_id
        && receipt.release_reservation_id == lease.reservation_id
        && receipt.fence_epoch == command.fence_epoch
        && receipt.binding == command.binding
        && receipt.provider == command.provider
        && receipt.expected_resource_version == command.expected_resource_version;
    if matches {
        Ok(())
    } else {
        Err(PepError::LedgerIntegrity)
    }
}

fn outcome(status: AdapterStatus) -> EnforcementOutcome {
    match status {
        AdapterStatus::Applied => EnforcementOutcome::Applied,
        AdapterStatus::Rejected => EnforcementOutcome::Rejected,
        AdapterStatus::Partial => EnforcementOutcome::Partial,
        AdapterStatus::Timeout | AdapterStatus::Unknown => EnforcementOutcome::Failed,
    }
}

fn evidence_digest(value: &AdapterOutcome) -> Result<String> {
    let encoded = serde_json::to_vec(value)?;
    Ok(format!("sha256:{:x}", Sha256::digest(encoded)))
}

fn unsigned() -> SignedDigestV1 {
    SignedDigestV1 {
        algorithm: SignatureAlgorithm::Ed25519,
        key_id: "pending".into(),
        digest: format!("sha256:{:064x}", 0),
        signature: "a".repeat(86),
    }
}
