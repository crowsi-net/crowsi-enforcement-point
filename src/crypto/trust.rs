use ed25519_dalek::VerifyingKey;

use crate::{
    EnforcementReceiptV2, IsolationCommandV2, PepError, Result, SignatureAlgorithm, validation,
};

#[derive(Clone)]
pub struct TrustedCommandKey {
    key_id: String,
    key: VerifyingKey,
    security_domain: String,
    deployment_id: String,
}

#[derive(Clone)]
pub struct TrustedReceiptKey {
    key_id: String,
    key: VerifyingKey,
}

impl TrustedCommandKey {
    /// Pins one PA key to one security domain and deployment.
    ///
    /// # Errors
    ///
    /// Rejects invalid scope, key identifiers, and weak Ed25519 keys.
    pub fn new(
        key_id: &str,
        key: [u8; 32],
        security_domain: &str,
        deployment_id: &str,
    ) -> Result<Self> {
        validation::identifier("key_id", key_id)?;
        validation::identifier("security_domain", security_domain)?;
        validation::identifier("deployment_id", deployment_id)?;
        Ok(Self {
            key_id: key_id.into(),
            key: verifying_key(key)?,
            security_domain: security_domain.into(),
            deployment_id: deployment_id.into(),
        })
    }

    pub(crate) fn verify(&self, command: &IsolationCommandV2) -> Result<()> {
        command.validate_contract()?;
        if command.signed.algorithm != SignatureAlgorithm::Ed25519
            || command.signed.key_id != self.key_id
            || command.security_domain != self.security_domain
            || command.deployment_id != self.deployment_id
        {
            return Err(PepError::Trust);
        }
        let signature = super::signature_bytes(&command.signed.signature)?;
        self.key
            .verify_strict(&super::digest_bytes(&command.signed.digest)?, &signature)
            .map_err(|_| PepError::Signature)
    }

    pub(crate) fn conflicts_with_receipt(&self, receipt: &TrustedReceiptKey) -> bool {
        self.key_id == receipt.key_id || self.key.to_bytes() == receipt.key.to_bytes()
    }
}

impl TrustedReceiptKey {
    /// Pins a PEP receipt verification key.
    ///
    /// # Errors
    ///
    /// Rejects malformed identifiers and invalid or weak Ed25519 keys.
    pub fn new(key_id: &str, key: [u8; 32]) -> Result<Self> {
        validation::identifier("key_id", key_id)?;
        Ok(Self {
            key_id: key_id.into(),
            key: verifying_key(key)?,
        })
    }

    /// Verifies a released `EnforcementReceiptV2`.
    ///
    /// # Errors
    ///
    /// Rejects malformed, untrusted, digest-mismatched, or forged receipts.
    pub fn verify(&self, receipt: &EnforcementReceiptV2) -> Result<()> {
        receipt.validate_contract()?;
        if receipt.signed.algorithm != SignatureAlgorithm::Ed25519
            || receipt.signed.key_id != self.key_id
        {
            return Err(PepError::Trust);
        }
        let signature = super::signature_bytes(&receipt.signed.signature)?;
        self.key
            .verify_strict(&super::digest_bytes(&receipt.signed.digest)?, &signature)
            .map_err(|_| PepError::Signature)
    }

    pub(crate) fn key_id(&self) -> &str {
        &self.key_id
    }
}

fn verifying_key(bytes: [u8; 32]) -> Result<VerifyingKey> {
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| PepError::Trust)?;
    if key.is_weak() {
        Err(PepError::Trust)
    } else {
        Ok(key)
    }
}
