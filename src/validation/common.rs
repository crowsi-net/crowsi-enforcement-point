use crate::{PepError, Result};

pub(crate) fn identifier(field: &str, value: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value.starts_with(|character: char| character.is_ascii_lowercase())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._:-".contains(&byte)
        });
    if valid { Ok(()) } else { invalid(field) }
}

pub(crate) fn opaque(field: &str, value: &str) -> Result<()> {
    if !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.chars().any(char::is_control)
    {
        Ok(())
    } else {
        invalid(field)
    }
}

pub(crate) fn digest(field: &str, value: &str) -> Result<()> {
    let valid = value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    });
    if valid { Ok(()) } else { invalid(field) }
}

pub(crate) fn signature(value: &str) -> Result<()> {
    if (43..=2048).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
    {
        Ok(())
    } else {
        invalid("signed.signature")
    }
}

pub(crate) fn invalid<T>(field: &str) -> Result<T> {
    Err(PepError::Validation(field.into()))
}
