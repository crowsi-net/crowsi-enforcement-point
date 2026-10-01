use time::{OffsetDateTime, format_description::well_known::Iso8601};

use crate::{PepError, Result};

pub(crate) fn timestamp(value: &str) -> Result<OffsetDateTime> {
    if value.len() != 24 || value.as_bytes().get(19) != Some(&b'.') || !value.ends_with('Z') {
        return Err(PepError::Validation("timestamp".into()));
    }
    OffsetDateTime::parse(value, &Iso8601::DEFAULT)
        .map_err(|_| PepError::Validation("timestamp".into()))
}

pub(crate) fn in_window(issued_at: &str, checked_at: &str, expires_at: &str) -> Result<bool> {
    let issued = timestamp(issued_at)?;
    let checked = timestamp(checked_at)?;
    let expires = timestamp(expires_at)?;
    Ok(issued <= checked && checked < expires)
}

pub(crate) fn short_window(issued_at: &str, expires_at: &str) -> Result<()> {
    let issued = timestamp(issued_at)?;
    let expires = timestamp(expires_at)?;
    let duration = expires - issued;
    if duration.is_positive() && duration.whole_milliseconds() <= 60_000 {
        Ok(())
    } else {
        Err(PepError::Validation("command time window".into()))
    }
}
