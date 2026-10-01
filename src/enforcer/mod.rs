mod outcome;
mod receipt;
mod request;

use std::sync::{Arc, Mutex};

use crate::ledger::Reservation;
use crate::{
    AdapterOutcome, ControlAction, ControlChannel, EnforcementAdapter, EnforcementReceiptV2,
    PepError, PepExecutionLeaseV2, PepLedger, ReceiptSigningPort, Result, SignatureAlgorithm,
    TrustedCommandKey, TrustedReceiptKey, validation,
};

pub struct EnforcementPoint {
    ledger: PepLedger,
    adapter: Arc<dyn EnforcementAdapter>,
    authority: TrustedCommandKey,
    receipt_signer: Arc<dyn ReceiptSigningPort>,
    receipt_authority: TrustedReceiptKey,
    clock: Arc<dyn crate::clock::TrustedClock>,
    execution: Mutex<()>,
}

impl EnforcementPoint {
    /// Creates a PEP bound to an external receipt signer and its public key.
    ///
    /// # Errors
    ///
    /// Rejects malformed or mismatched signer key identifiers.
    pub fn new<A, S>(
        ledger: PepLedger,
        adapter: Arc<A>,
        authority: TrustedCommandKey,
        receipt_signer: Arc<S>,
        receipt_authority: TrustedReceiptKey,
    ) -> Result<Self>
    where
        A: EnforcementAdapter + 'static,
        S: ReceiptSigningPort + 'static,
    {
        validation::identifier("receipt_signer.key_id", receipt_signer.key_id())?;
        if receipt_signer.key_id() != receipt_authority.key_id()
            || authority.conflicts_with_receipt(&receipt_authority)
        {
            return Err(PepError::Trust);
        }
        Ok(Self {
            ledger,
            adapter,
            authority,
            receipt_signer,
            receipt_authority,
            clock: Arc::new(crate::clock::SystemTrustedClock),
            execution: Mutex::new(()),
        })
    }

    /// Applies one cryptographically bound execution lease at most once.
    ///
    /// # Errors
    ///
    /// Rejects invalid trust, time, recovery path, or durable ledger state.
    pub fn execute(&self, lease: &PepExecutionLeaseV2) -> Result<EnforcementReceiptV2> {
        self.execute_at(lease, &self.clock.now())
    }

    /// Executes against a fixed conformance time in debug/test builds.
    ///
    /// # Errors
    ///
    /// Rejects invalid trust, time, recovery path, or durable ledger state.
    #[cfg(debug_assertions)]
    pub fn execute_at_for_test(
        &self,
        lease: &PepExecutionLeaseV2,
        applied_at: &str,
    ) -> Result<EnforcementReceiptV2> {
        self.execute_at(lease, applied_at)
    }

    fn execute_at(
        &self,
        lease: &PepExecutionLeaseV2,
        applied_at: &str,
    ) -> Result<EnforcementReceiptV2> {
        let _guard = self
            .execution
            .lock()
            .map_err(|_| PepError::LedgerIntegrity)?;
        validation::timestamp(applied_at)?;
        self.ledger.observe_time(applied_at)?;
        lease.validate_contract()?;
        self.authority.verify(&lease.command)?;
        if !validation::in_window(
            &lease.command.issued_at,
            applied_at,
            &lease.command.expires_at,
        )? {
            return Err(PepError::TimeWindow);
        }
        recovery_path(lease)?;
        match self.ledger.reserve(lease)? {
            Reservation::Replay(value) => {
                self.receipt_authority.verify(&value)?;
                receipt::matches_lease(&value, lease)?;
                return Ok(*value);
            }
            Reservation::Pending(reserved_at) => {
                let value = receipt::create(
                    lease,
                    &reserved_at,
                    &AdapterOutcome::unknown("unresolved-prior-attempt"),
                )?;
                return self.sign_receipt(value);
            }
            Reservation::New => {}
        }
        let request = request::provider(lease);
        let outcome = outcome::normalize(&request, self.adapter.apply(&request));
        let value = receipt::create(lease, applied_at, &outcome)?;
        let value = self.sign_receipt(value)?;
        self.ledger.finalize(lease, &value)?;
        Ok(value)
    }

    fn sign_receipt(&self, mut value: EnforcementReceiptV2) -> Result<EnforcementReceiptV2> {
        value.signed.algorithm = SignatureAlgorithm::Ed25519;
        value.signed.key_id = self.receipt_signer.key_id().into();
        value.signed.digest = value.payload_digest();
        value.validate_contract()?;
        value.signed.signature = self.receipt_signer.sign_digest(&value.signed.digest)?;
        self.receipt_authority.verify(&value)?;
        Ok(value)
    }
}

fn recovery_path(lease: &PepExecutionLeaseV2) -> Result<()> {
    let binding = &lease.command.binding;
    if binding.action == ControlAction::Restore
        && binding.channel != ControlChannel::EmergencyConsole
    {
        return Err(PepError::Validation("command.restore-channel".into()));
    }
    Ok(())
}
