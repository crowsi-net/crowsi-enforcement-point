mod support;

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use crowsi_enforcement_point::{
    EnforcementOutcome, EnforcementPoint, MemoryProvider, PepExecutionLeaseV2, PepLedger,
    ProviderKind, ResourceRecord, ResourceState, TrustedCommandKey, TrustedReceiptKey,
};
use support::TestReceiptSigner;

#[test]
fn exact_pa_lease_generates_the_released_signed_receipt_bytes() {
    let lease: PepExecutionLeaseV2 = serde_json::from_str(include_str!(
        "../fixtures/conformance/v1/pep-execution-lease-v2.json"
    ))
    .unwrap();
    let command_manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../fixtures/conformance/v1/pep-command-trust-manifest-v1.json"
    ))
    .unwrap();
    let public = manifest_key(&command_manifest, "command_verifier");
    let command_key = TrustedCommandKey::new(
        "command.control.1",
        public,
        "customer-hat",
        "deployment.production.1",
    )
    .unwrap();
    let provider = Arc::new(MemoryProvider::new());
    provider
        .register(ResourceRecord {
            security_domain: "customer-hat".into(),
            deployment_id: "deployment.production.1".into(),
            resource_uri: "incus://project/default/instance/worker-a".into(),
            provider: "crowsi-enforcer-incus".into(),
            kind: ProviderKind::Incus,
            resource_version: "incus-etag-7".into(),
            latest_fence: 0,
            state: ResourceState::Connected,
        })
        .unwrap();
    let signer = Arc::new(TestReceiptSigner::from_seed("receipt.fixture.1", [8; 32]));
    let receipt_manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../fixtures/conformance/v1/pep-receipt-trust-manifest-v1.json"
    ))
    .unwrap();
    let receipt_public = manifest_key(&receipt_manifest, "receipt_verifier");
    assert_eq!(receipt_public, signer.verifying_key());
    let receipt_key = TrustedReceiptKey::new("receipt.fixture.1", receipt_public).unwrap();
    let point = EnforcementPoint::new(
        PepLedger::open_in_memory().unwrap(),
        provider,
        command_key,
        signer,
        receipt_key.clone(),
    )
    .unwrap();

    let receipt = point
        .execute_at_for_test(&lease, "2026-07-29T00:02:01.000Z")
        .unwrap();
    receipt_key.verify(&receipt).unwrap();
    assert_eq!(
        format!("{}\n", serde_json::to_string_pretty(&receipt).unwrap()),
        include_str!("../fixtures/conformance/v1/enforcement-receipt-v2.json")
    );
    assert_eq!(receipt.outcome, EnforcementOutcome::Applied);
}

fn manifest_key(manifest: &serde_json::Value, field: &str) -> [u8; 32] {
    URL_SAFE_NO_PAD
        .decode(manifest[field]["public_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}
