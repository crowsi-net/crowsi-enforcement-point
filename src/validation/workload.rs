use crate::Result;

pub(super) fn spiffe(value: &str) -> Result<()> {
    let remainder = value
        .strip_prefix("spiffe://")
        .filter(|_| value.len() <= 256)
        .ok_or_else(invalid)?;
    let (trust_domain, path) = remainder.split_once('/').ok_or_else(invalid)?;
    if valid_trust_domain(trust_domain) && valid_path(path) {
        Ok(())
    } else {
        Err(invalid())
    }
}

fn valid_trust_domain(value: &str) -> bool {
    !value.is_empty() && value.len() <= 253 && value.split('.').all(valid_label)
}

fn valid_label(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn valid_path(value: &str) -> bool {
    !value.is_empty() && value.split('/').all(valid_segment)
}

fn valid_segment(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(byte))
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(byte))
}

fn invalid() -> crate::PepError {
    crate::PepError::Validation("workload".into())
}
