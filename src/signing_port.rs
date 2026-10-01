use crate::Result;

/// Delegates receipt signatures to an external HSM, TPM, or credential broker.
pub trait ReceiptSigningPort: Send + Sync {
    /// Returns the pinned public key identifier used by this signer.
    fn key_id(&self) -> &str;

    /// Signs the 32-byte value represented by a lowercase `sha256:` digest.
    ///
    /// # Errors
    ///
    /// Returns an error when the protected key cannot produce a signature.
    fn sign_digest(&self, digest: &str) -> Result<String>;
}
