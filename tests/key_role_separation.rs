mod support;

use std::sync::Arc;

use crowsi_enforcement_point::{
    EnforcementPoint, MemoryProvider, PepError, PepLedger, ReceiptSigningPort, TrustedCommandKey,
    TrustedReceiptKey,
};
use support::{TestCommandSigner, TestReceiptSigner};

#[test]
fn command_and_receipt_roles_reject_reused_key_material() {
    let command = TestCommandSigner::from_seed("command-key", [71; 32]);
    let receipt = Arc::new(TestReceiptSigner::from_seed("receipt-key", [71; 32]));

    assert!(matches!(point(&command, receipt), Err(PepError::Trust)));
}

#[test]
fn command_and_receipt_roles_reject_reused_key_identifier() {
    let command = TestCommandSigner::from_seed("shared-key", [72; 32]);
    let receipt = Arc::new(TestReceiptSigner::from_seed("shared-key", [73; 32]));

    assert!(matches!(point(&command, receipt), Err(PepError::Trust)));
}

fn point(
    command: &TestCommandSigner,
    receipt: Arc<TestReceiptSigner>,
) -> crowsi_enforcement_point::Result<EnforcementPoint> {
    let command_key = TrustedCommandKey::new(
        command.key_id(),
        command.verifying_key(),
        "domain:personal",
        "deployment.personal.1",
    )?;
    let receipt_key = TrustedReceiptKey::new(receipt.key_id(), receipt.verifying_key())?;
    EnforcementPoint::new(
        PepLedger::open_in_memory()?,
        Arc::new(MemoryProvider::new()),
        command_key,
        receipt,
        receipt_key,
    )
}
