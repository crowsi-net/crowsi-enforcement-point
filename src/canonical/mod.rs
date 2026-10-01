mod command;
mod encoder;
mod receipt;

use sha2::{Digest, Sha256};

use crate::{EnforcementReceiptV2, IsolationCommandV2};

pub(crate) use encoder::{Encoder, binding};

pub(crate) trait CanonicalV2 {
    fn payload(&self) -> Vec<u8>;
}

pub(crate) fn digest<T: CanonicalV2>(value: &T) -> String {
    let hash = Sha256::digest(value.payload());
    let mut encoded = String::with_capacity(71);
    encoded.push_str("sha256:");
    for byte in hash {
        use std::fmt::Write as _;
        write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

impl IsolationCommandV2 {
    #[must_use]
    pub fn payload_digest(&self) -> String {
        digest(self)
    }
}

impl EnforcementReceiptV2 {
    #[must_use]
    pub fn payload_digest(&self) -> String {
        digest(self)
    }
}
