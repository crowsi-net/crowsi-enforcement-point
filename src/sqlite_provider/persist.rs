use rusqlite::{OptionalExtension, Transaction, params};

use crate::{AdapterOutcome, PepError, ProviderRequest, Result};

pub(crate) fn finish(
    transaction: Transaction<'_>,
    request: &ProviderRequest,
    outcome: AdapterOutcome,
) -> Result<AdapterOutcome> {
    transaction.execute(
        "INSERT INTO provider_operations (
           command_jti, command_digest, outcome_json
         ) VALUES (?1, ?2, ?3)",
        params![
            request.command_jti,
            request.command_digest,
            serde_json::to_string(&outcome)?
        ],
    )?;
    transaction.commit()?;
    Ok(outcome)
}

pub(crate) fn previous(
    transaction: &Transaction<'_>,
    command_jti: &str,
) -> Result<Option<(String, String)>> {
    transaction
        .query_row(
            "SELECT command_digest, outcome_json FROM provider_operations
             WHERE command_jti = ?1",
            [command_jti],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(PepError::from)
}

pub(crate) fn storage_unknown(_: PepError) -> AdapterOutcome {
    AdapterOutcome::unknown("adapter-storage-unavailable")
}
