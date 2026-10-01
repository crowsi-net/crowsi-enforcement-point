use time::OffsetDateTime;

pub(crate) trait TrustedClock: Send + Sync {
    fn now(&self) -> String;
}

pub(crate) struct SystemTrustedClock;

impl TrustedClock for SystemTrustedClock {
    fn now(&self) -> String {
        normalized(OffsetDateTime::now_utc())
    }
}

pub(crate) fn normalized(value: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        value.year(),
        u8::from(value.month()),
        value.day(),
        value.hour(),
        value.minute(),
        value.second(),
        value.nanosecond() / 1_000_000
    )
}
