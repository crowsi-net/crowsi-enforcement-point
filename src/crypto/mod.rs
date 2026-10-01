mod trust;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::{PepError, Result};

pub use trust::{TrustedCommandKey, TrustedReceiptKey};

pub(crate) fn digest_bytes(value: &str) -> Result<[u8; 32]> {
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

pub(crate) fn signature_bytes(value: &str) -> Result<ed25519_dalek::Signature> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| PepError::Signature)?;
    ed25519_dalek::Signature::from_slice(&bytes).map_err(|_| PepError::Signature)
}
