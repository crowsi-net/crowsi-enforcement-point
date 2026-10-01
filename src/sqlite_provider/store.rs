use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::{Connection, OptionalExtension, params};

use crate::{PepError, ResourceRecord, Result, sqlite_provider_schema};

pub struct SqliteProvider {
    pub(crate) connection: Mutex<Connection>,
}

impl SqliteProvider {
    /// Opens a process-local provider conformance database.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` initialization or schema validation fails.
    pub fn open_in_memory() -> Result<Self> {
        Self::finish_open(Connection::open_in_memory()?)
    }

    /// Opens a durable debug conformance database.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` initialization or schema validation fails.
    #[cfg(debug_assertions)]
    pub fn open_for_test(path: &Path) -> Result<Self> {
        Self::finish_open(Connection::open(path)?)
    }

    /// Opens a durable provider database in an owner-only canonical directory.
    ///
    /// # Errors
    ///
    /// Rejects unsafe paths, ownership, permissions, identity changes, or schema.
    #[cfg(unix)]
    pub fn open_secure(path: &Path) -> Result<Self> {
        Self::finish_open(crate::ledger_file::open(path)?)
    }

    fn finish_open(connection: Connection) -> Result<Self> {
        connection.pragma_update(None, "trusted_schema", "OFF")?;
        connection.pragma_update(None, "journal_mode", "DELETE")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        sqlite_provider_schema::migrate(&connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    /// Registers the provider's initial authoritative resource state.
    ///
    /// # Errors
    ///
    /// Rejects duplicate, malformed, or non-representable records.
    pub fn register(&self, record: &ResourceRecord) -> Result<()> {
        if record.resource_uri.is_empty()
            || record.security_domain.is_empty()
            || record.deployment_id.is_empty()
            || record.provider.is_empty()
            || record.resource_version.is_empty()
            || record.resource_uri.len() > 512
            || record.security_domain.len() > 256
            || record.deployment_id.len() > 256
            || record.provider.len() > 256
            || record.resource_version.len() > 256
            || record.latest_fence > i64::MAX as u64
        {
            return Err(PepError::Validation("provider resource".into()));
        }
        self.lock()?.execute(
            "INSERT INTO provider_resources (
               resource_uri, security_domain, deployment_id, provider, kind,
               resource_version, latest_fence, state
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                record.resource_uri,
                record.security_domain,
                record.deployment_id,
                record.provider,
                super::codec::kind_code(record.kind),
                record.resource_version,
                record.latest_fence,
                record.state.code()
            ],
        )?;
        Ok(())
    }

    /// Reads the local conformance provider's authoritative state.
    ///
    /// # Errors
    ///
    /// Returns an error for storage failure or invalid persisted enum values.
    pub fn snapshot(&self, uri: &str) -> Result<Option<ResourceRecord>> {
        let connection = self.lock()?;
        resource(&connection, uri)
    }

    pub(crate) fn lock(&self) -> Result<MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| PepError::LedgerIntegrity)
    }
}

pub(crate) fn resource(connection: &Connection, uri: &str) -> Result<Option<ResourceRecord>> {
    let row = connection
        .query_row(
            "SELECT security_domain, deployment_id, provider, kind,
                    resource_version, latest_fence, state
             FROM provider_resources WHERE resource_uri = ?1",
            [uri],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, u64>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(domain, deployment, provider, kind, version, fence, state)| {
            Ok(ResourceRecord {
                security_domain: domain,
                deployment_id: deployment,
                resource_uri: uri.into(),
                provider,
                kind: super::codec::kind(&kind).ok_or(PepError::LedgerIntegrity)?,
                resource_version: version,
                latest_fence: fence,
                state: super::codec::state(&state).ok_or(PepError::LedgerIntegrity)?,
            })
        },
    )
    .transpose()
}
