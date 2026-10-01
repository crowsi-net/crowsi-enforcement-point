use rusqlite::Connection;

use crate::{PepError, Result};

const APPLICATION_ID: i64 = 0x4352_5350;
const VERSION: i64 = 2;

pub(crate) fn migrate(connection: &Connection) -> Result<()> {
    let application_id: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if !matches!(application_id, 0 | APPLICATION_ID) || !matches!(version, 0 | VERSION) {
        return Err(PepError::LedgerIntegrity);
    }
    connection.execute_batch(
        "BEGIN IMMEDIATE;
         CREATE TABLE IF NOT EXISTS provider_resources (
           resource_uri TEXT PRIMARY KEY,
           security_domain TEXT NOT NULL,
           deployment_id TEXT NOT NULL,
           provider TEXT NOT NULL,
           kind TEXT NOT NULL CHECK(kind IN (
             'host', 'host-firewall', 'cloud-provider', 'incus'
           )),
           resource_version TEXT NOT NULL,
           latest_fence INTEGER NOT NULL CHECK(latest_fence >= 0),
           state TEXT NOT NULL CHECK(state IN (
             'connected', 'isolated', 'revoked', 'indeterminate'
           ))
         ) STRICT;
         CREATE TABLE IF NOT EXISTS provider_operations (
           command_jti TEXT PRIMARY KEY,
           command_digest TEXT NOT NULL,
           outcome_json TEXT NOT NULL
         ) STRICT;
         PRAGMA application_id = 1129468752;
         PRAGMA user_version = 2;
         COMMIT;",
    )?;
    verify(connection)
}

fn verify(connection: &Connection) -> Result<()> {
    let expected = [
        (
            "provider_operations",
            "CREATE TABLE provider_operations (
              command_jti TEXT PRIMARY KEY,
              command_digest TEXT NOT NULL,
              outcome_json TEXT NOT NULL
            ) STRICT",
        ),
        (
            "provider_resources",
            "CREATE TABLE provider_resources (
              resource_uri TEXT PRIMARY KEY, security_domain TEXT NOT NULL,
              deployment_id TEXT NOT NULL, provider TEXT NOT NULL,
              kind TEXT NOT NULL CHECK(kind IN (
                'host', 'host-firewall', 'cloud-provider', 'incus'
              )),
              resource_version TEXT NOT NULL,
              latest_fence INTEGER NOT NULL CHECK(latest_fence >= 0),
              state TEXT NOT NULL CHECK(state IN (
                'connected', 'isolated', 'revoked', 'indeterminate'
              ))
            ) STRICT",
        ),
    ];
    let mut statement = connection.prepare(
        "SELECT name, sql FROM sqlite_schema
         WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let actual = rows.collect::<std::result::Result<Vec<_>, _>>()?;
    let invalid = actual.len() != expected.len()
        || actual
            .iter()
            .zip(expected)
            .any(|((name, sql), (expected_name, expected_sql))| {
                name != expected_name || normalized(sql) != normalized(expected_sql)
            });
    if invalid {
        return Err(PepError::LedgerIntegrity);
    }
    Ok(())
}

fn normalized(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use super::migrate;
    use crate::PepError;

    #[test]
    fn legacy_or_weakened_provider_schema_is_rejected() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE provider_operations (
                   idempotency_key TEXT PRIMARY KEY,
                   command_digest TEXT,
                   outcome_json TEXT
                 ) STRICT;
                 CREATE TABLE provider_resources (
                   resource_uri TEXT PRIMARY KEY,
                   security_domain TEXT,
                   provider TEXT,
                   resource_version INTEGER,
                   latest_fence INTEGER,
                   state TEXT
                 ) STRICT;
                 PRAGMA application_id = 1129468752;
                 PRAGMA user_version = 1;",
            )
            .unwrap();
        assert!(matches!(
            migrate(&connection),
            Err(PepError::LedgerIntegrity)
        ));
    }
}
