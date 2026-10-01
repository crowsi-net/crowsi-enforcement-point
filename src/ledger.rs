use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::{EnforcementReceiptV2, PepError, PepExecutionLeaseV2, Result, schema};

pub struct PepLedger {
    connection: Mutex<Connection>,
}

pub(crate) enum Reservation {
    New,
    Replay(Box<EnforcementReceiptV2>),
    Pending(String),
}

impl PepLedger {
    /// Opens a process-local V2 conformance ledger.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` initialization or schema validation fails.
    pub fn open_in_memory() -> Result<Self> {
        Self::finish_open(Connection::open_in_memory()?)
    }

    #[cfg(debug_assertions)]
    /// Opens a V2 ledger without production file-ownership checks.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` initialization or schema validation fails.
    pub fn open_for_test(path: &Path) -> Result<Self> {
        Self::finish_open(Connection::open(path)?)
    }

    #[cfg(unix)]
    /// Opens a V2 ledger with strict owner and file-mode checks.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe file metadata or invalid storage/schema state.
    pub fn open_secure(path: &Path) -> Result<Self> {
        Self::finish_open(crate::ledger_file::open(path)?)
    }

    fn finish_open(connection: Connection) -> Result<Self> {
        connection.pragma_update(None, "trusted_schema", "OFF")?;
        connection.pragma_update(None, "journal_mode", "DELETE")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        schema::migrate(&connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub(crate) fn reserve(&self, lease: &PepExecutionLeaseV2) -> Result<Reservation> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = transaction
            .query_row(
                "SELECT command_digest, receipt_json, reserved_at
                 FROM enforcement_attempts
                 WHERE command_jti = ?1 OR reservation_id = ?2",
                params![lease.command.jti, lease.reservation_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;
        let result = if let Some((digest, receipt, reserved_at)) = existing {
            if digest != lease.command_digest {
                return Err(PepError::IdempotencyConflict);
            }
            match receipt {
                Some(value) => Reservation::Replay(Box::new(serde_json::from_str(&value)?)),
                None => Reservation::Pending(reserved_at),
            }
        } else {
            transaction.execute(
                "INSERT INTO enforcement_attempts (
                   command_jti, reservation_id, command_digest, outcome, reserved_at
                 ) VALUES (?1, ?2, ?3, 'reserved', ?4)",
                params![
                    lease.command.jti,
                    lease.reservation_id,
                    lease.command_digest,
                    lease.reserved_at
                ],
            )?;
            Reservation::New
        };
        transaction.commit()?;
        Ok(result)
    }

    pub(crate) fn observe_time(&self, observed_at: &str) -> Result<()> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous = transaction
            .query_row(
                "SELECT observed_at FROM trusted_time_watermark WHERE singleton = 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if previous.as_deref().is_some_and(|value| observed_at < value) {
            return Err(PepError::ClockRollback);
        }
        transaction.execute(
            "INSERT INTO trusted_time_watermark (singleton, observed_at) VALUES (1, ?1)
             ON CONFLICT(singleton) DO UPDATE SET observed_at = excluded.observed_at
             WHERE excluded.observed_at > trusted_time_watermark.observed_at",
            [observed_at],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn finalize(
        &self,
        lease: &PepExecutionLeaseV2,
        receipt: &EnforcementReceiptV2,
    ) -> Result<()> {
        let outcome = receipt.outcome.code();
        let changed = self.lock()?.execute(
            "UPDATE enforcement_attempts
             SET outcome = ?1, receipt_json = ?2, finalized_at = ?3
             WHERE command_jti = ?4 AND command_digest = ?5 AND outcome = 'reserved'",
            params![
                outcome,
                serde_json::to_string(receipt)?,
                receipt.applied_at,
                lease.command.jti,
                lease.command_digest
            ],
        )?;
        if changed != 1 {
            return Err(PepError::LedgerIntegrity);
        }
        Ok(())
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| PepError::LedgerIntegrity)
    }
}
