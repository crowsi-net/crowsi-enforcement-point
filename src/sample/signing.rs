use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use crowsi_enforcement_point::{
    IsolationCommandV2, PepError, ReceiptSigningPort, Result, SignatureAlgorithm,
};
use ed25519_dalek::{Signer as _, SigningKey};

pub(super) struct SampleCommandSigner {
    key_id: String,
    key: SigningKey,
}

pub(super) struct SampleReceiptSigner {
    key_id: String,
    key: SigningKey,
}

impl SampleCommandSigner {
    pub(super) fn new() -> Self {
        Self {
            key_id: "command.sample.1".into(),
            key: SigningKey::from_bytes(&[5; 32]),
        }
    }

    pub(super) fn verifying_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    pub(super) fn sign(&self, mut command: IsolationCommandV2) -> Result<IsolationCommandV2> {
        command.signed.algorithm = SignatureAlgorithm::Ed25519;
        command.signed.key_id.clone_from(&self.key_id);
        command.signed.digest = command.payload_digest();
        command.signed.signature = sign(&self.key, &command.signed.digest)?;
        command.validate_contract()?;
        Ok(command)
    }
}

impl SampleReceiptSigner {
    pub(super) fn new() -> Self {
        Self {
            key_id: "receipt.sample.1".into(),
            key: SigningKey::from_bytes(&[6; 32]),
        }
    }

    pub(super) fn verifying_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
}

impl ReceiptSigningPort for SampleReceiptSigner {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn sign_digest(&self, digest: &str) -> Result<String> {
        sign(&self.key, digest)
    }
}

fn sign(key: &SigningKey, digest: &str) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(key.sign(&digest_bytes(digest)?).to_bytes()))
}

fn digest_bytes(value: &str) -> Result<[u8; 32]> {
    let hex = value.strip_prefix("sha256:").ok_or(PepError::Signature)?;
    if hex.len() != 64 {
        return Err(PepError::Signature);
    }
    let mut bytes = [0_u8; 32];
    for (index, target) in bytes.iter_mut().enumerate() {
        *target = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .map_err(|_| PepError::Signature)?;
    }
    Ok(bytes)
}
