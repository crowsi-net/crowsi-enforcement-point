use std::sync::Arc;

use crowsi_enforcement_point::{
    ActionBindingV1, ControlAction, ControlChannel, EnforcementPoint, FaultMode, MemoryProvider,
    PepExecutionLeaseV2, PepLedger, ProviderKind, ResourceRecord, ResourceState, Result,
    SignatureAlgorithm, SignedDigestV1, TrustedCommandKey, TrustedReceiptKey,
};
use time::{Duration, OffsetDateTime};

use super::signing::{SampleCommandSigner, SampleReceiptSigner};

pub(super) struct Setup {
    signer: SampleCommandSigner,
    pub(super) point: EnforcementPoint,
    issued_at: String,
    reserved_at: String,
    expires_at: String,
}

impl Setup {
    pub(super) fn new(fault: FaultMode) -> Result<Self> {
        let signer = SampleCommandSigner::new();
        let receipt_signer = Arc::new(SampleReceiptSigner::new());
        let trusted = TrustedCommandKey::new(
            "command.sample.1",
            signer.verifying_key(),
            "customer-sample",
            "deployment.sample.1",
        )?;
        let provider = Arc::new(MemoryProvider::new());
        provider.register(resource())?;
        provider.set_next_fault(fault);
        let current = OffsetDateTime::now_utc();
        Ok(Self {
            signer,
            point: EnforcementPoint::new(
                PepLedger::open_in_memory()?,
                provider,
                trusted,
                receipt_signer.clone(),
                TrustedReceiptKey::new("receipt.sample.1", receipt_signer.verifying_key())?,
            )?,
            issued_at: timestamp(current - Duration::seconds(10)),
            reserved_at: timestamp(current - Duration::seconds(5)),
            expires_at: timestamp(current + Duration::seconds(50)),
        })
    }

    pub(super) fn lease(&self, serial: u64) -> Result<PepExecutionLeaseV2> {
        let command = self
            .signer
            .sign(command(serial, &self.issued_at, &self.expires_at))?;
        Ok(PepExecutionLeaseV2 {
            schema: "crowsi://control/pep-execution-lease/v2".into(),
            reservation_id: command.release_reservation_id.clone(),
            command_digest: command.payload_digest(),
            command,
            reserved_at: self.reserved_at.clone(),
        })
    }
}

fn resource() -> ResourceRecord {
    ResourceRecord {
        security_domain: "customer-sample".into(),
        deployment_id: "deployment.sample.1".into(),
        resource_uri: "host://sample/firewall".into(),
        provider: "crowsi-enforcer-host-firewall".into(),
        kind: ProviderKind::HostFirewall,
        resource_version: "etag-3".into(),
        latest_fence: 6,
        state: ResourceState::Connected,
    }
}

fn command(
    serial: u64,
    issued_at: &str,
    expires_at: &str,
) -> crowsi_enforcement_point::IsolationCommandV2 {
    crowsi_enforcement_point::IsolationCommandV2 {
        schema: "crowsi://control/isolation-command/v2".into(),
        command_id: format!("command.sample.{serial}"),
        jti: format!("jti.command.sample.{serial}"),
        security_domain: "customer-sample".into(),
        deployment_id: "deployment.sample.1".into(),
        incident_id: "incident.sample.1".into(),
        target_id: "host://sample/firewall".into(),
        release_id: format!("release.{serial}"),
        release_digest: format!("sha256:{:064x}", 10 + serial),
        checkpoint_id: format!("checkpoint.{serial}"),
        checkpoint_digest: format!("sha256:{:064x}", 20 + serial),
        checkpoint_sequence: serial,
        release_reservation_id: format!("release-reservation.{serial}"),
        enforcement_grant_jti: format!("jti.grant.{serial}"),
        decision_id: format!("decision.{serial}"),
        pairwise_subject: "subject-sample".into(),
        actor: "operator-sample".into(),
        device: "device-sample".into(),
        workload: "spiffe://crowsi.local/rescue-console/sample".into(),
        profile: "security-operator".into(),
        proof_key_ref: "proof-key-sample".into(),
        revocation_epoch: 7,
        binding: binding(),
        provider: "crowsi-enforcer-host-firewall".into(),
        previous_fence_epoch: 6,
        fence_epoch: 7,
        expected_resource_version: "etag-3".into(),
        issued_at: issued_at.into(),
        expires_at: expires_at.into(),
        signed: unsigned(),
    }
}

fn binding() -> ActionBindingV1 {
    ActionBindingV1 {
        audience: "crowsi-enforcer-host-firewall".into(),
        resource: "host://sample/firewall".into(),
        action: ControlAction::Quarantine,
        purpose: "incident-containment".into(),
        channel: ControlChannel::EmergencyConsole,
    }
}

fn unsigned() -> SignedDigestV1 {
    SignedDigestV1 {
        algorithm: SignatureAlgorithm::Ed25519,
        key_id: "command.sample.1".into(),
        digest: format!("sha256:{:064x}", 0),
        signature: "a".repeat(86),
    }
}

fn timestamp(value: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        value.year(),
        u8::from(value.month()),
        value.day(),
        value.hour(),
        value.minute(),
        value.second(),
        value.nanosecond() / 1_000_000
    )
}
