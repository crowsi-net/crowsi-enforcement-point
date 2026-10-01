#![allow(dead_code)]

mod signing;

use std::sync::Arc;

use crowsi_enforcement_point::{
    ActionBindingV1, ControlAction, ControlChannel, EnforcementPoint, MemoryProvider,
    PepExecutionLeaseV2, PepLedger, ProviderKind, ResourceRecord, ResourceState,
    SignatureAlgorithm, SignedDigestV1, TrustedCommandKey, TrustedReceiptKey,
};
pub use signing::{TestCommandSigner, TestReceiptSigner};

pub const APPLIED_AT: &str = "2026-07-29T00:02:00.000Z";

pub struct Fixture {
    pub command_signer: TestCommandSigner,
    pub receipt_signer: Arc<TestReceiptSigner>,
    pub provider: Arc<MemoryProvider>,
    pub point: EnforcementPoint,
}

impl Fixture {
    pub fn new() -> Self {
        let command_signer = TestCommandSigner::from_seed("command.fixture.1", [7; 32]);
        let receipt_signer = Arc::new(TestReceiptSigner::from_seed("receipt.fixture.1", [8; 32]));
        let trusted = TrustedCommandKey::new(
            "command.fixture.1",
            command_signer.verifying_key(),
            "customer-sample",
            "deployment.sample.1",
        )
        .unwrap();
        let provider = Arc::new(MemoryProvider::new());
        provider.register(resource()).unwrap();
        let point = EnforcementPoint::new(
            PepLedger::open_in_memory().unwrap(),
            provider.clone(),
            trusted,
            receipt_signer.clone(),
            TrustedReceiptKey::new("receipt.fixture.1", receipt_signer.verifying_key()).unwrap(),
        )
        .unwrap();
        Self {
            command_signer,
            receipt_signer,
            provider,
            point,
        }
    }

    pub fn lease(
        &self,
        serial: u64,
        expected_version: &str,
        previous_fence: u64,
        fence: u64,
    ) -> PepExecutionLeaseV2 {
        let command = command(serial, expected_version, previous_fence, fence);
        let command = self.command_signer.sign(command).unwrap();
        PepExecutionLeaseV2 {
            schema: "crowsi://control/pep-execution-lease/v2".into(),
            reservation_id: command.release_reservation_id.clone(),
            command_digest: command.payload_digest(),
            command,
            reserved_at: "2026-07-29T00:01:45.000Z".into(),
        }
    }
}

pub fn resource() -> ResourceRecord {
    ResourceRecord {
        security_domain: "customer-sample".into(),
        deployment_id: "deployment.sample.1".into(),
        resource_uri: "host://device-a/firewall".into(),
        provider: "crowsi-enforcer-host-firewall".into(),
        kind: ProviderKind::HostFirewall,
        resource_version: "etag-4".into(),
        latest_fence: 8,
        state: ResourceState::Connected,
    }
}

pub fn command(
    serial: u64,
    expected_version: &str,
    previous_fence: u64,
    fence: u64,
) -> crowsi_enforcement_point::IsolationCommandV2 {
    crowsi_enforcement_point::IsolationCommandV2 {
        schema: "crowsi://control/isolation-command/v2".into(),
        command_id: format!("command.v2.{serial}"),
        jti: format!("jti.command.v2.{serial}"),
        security_domain: "customer-sample".into(),
        deployment_id: "deployment.sample.1".into(),
        incident_id: "incident.sample.1".into(),
        target_id: "host://device-a/firewall".into(),
        release_id: format!("release.{serial}"),
        release_digest: format!("sha256:{:064x}", 11 + serial),
        checkpoint_id: format!("checkpoint.{serial}"),
        checkpoint_digest: format!("sha256:{:064x}", 21 + serial),
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
        binding: ActionBindingV1 {
            audience: "crowsi-enforcer-host-firewall".into(),
            resource: "host://device-a/firewall".into(),
            action: ControlAction::Quarantine,
            purpose: "incident-containment".into(),
            channel: ControlChannel::EmergencyConsole,
        },
        provider: "crowsi-enforcer-host-firewall".into(),
        previous_fence_epoch: previous_fence,
        fence_epoch: fence,
        expected_resource_version: expected_version.into(),
        issued_at: "2026-07-29T00:01:30.000Z".into(),
        expires_at: "2026-07-29T00:02:30.000Z".into(),
        signed: SignedDigestV1 {
            algorithm: SignatureAlgorithm::Ed25519,
            key_id: "command.fixture.1".into(),
            digest: format!("sha256:{:064x}", 0),
            signature: "a".repeat(86),
        },
    }
}
