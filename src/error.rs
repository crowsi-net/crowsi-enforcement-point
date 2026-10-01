use thiserror::Error;

pub type Result<T> = std::result::Result<T, PepError>;

#[derive(Debug, Error)]
pub enum PepError {
    #[error("command validation failed: {0}")]
    Validation(String),
    #[error("command signature is invalid")]
    Signature,
    #[error("command authority or security domain is not trusted")]
    Trust,
    #[error("command is outside its trusted execution window")]
    TimeWindow,
    #[error("trusted execution time moved behind its durable watermark")]
    ClockRollback,
    #[error("idempotency key was reused for a different command")]
    IdempotencyConflict,
    #[error("enforcement ledger storage failed")]
    Storage(#[from] rusqlite::Error),
    #[error("enforcement ledger identity, path, or schema is invalid")]
    LedgerIntegrity,
    #[error("enforcement ledger serialization failed")]
    Serialization(#[from] serde_json::Error),
}
