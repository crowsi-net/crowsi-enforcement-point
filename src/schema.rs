use rusqlite::Connection;

use crate::{PepError, Result};

const APPLICATION_ID: i64 = 0x4352_5045;

pub(crate) fn migrate(connection: &Connection) -> Result<()> {
    let application_id: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if !matches!(application_id, 0 | APPLICATION_ID) || !matches!(version, 0 | 3) {
        return Err(PepError::LedgerIntegrity);
    }
    connection.execute_batch(
        "BEGIN IMMEDIATE;
         CREATE TABLE IF NOT EXISTS enforcement_attempts (
           command_jti TEXT PRIMARY KEY,
           reservation_id TEXT NOT NULL UNIQUE,
           command_digest TEXT NOT NULL,
           outcome TEXT NOT NULL CHECK(outcome IN (
             'reserved', 'applied', 'rejected', 'failed', 'partial'
           )),
           receipt_json TEXT,
           reserved_at TEXT NOT NULL,
           finalized_at TEXT,
           CHECK(
             (outcome = 'reserved' AND receipt_json IS NULL AND finalized_at IS NULL)
             OR
             (outcome != 'reserved' AND receipt_json IS NOT NULL AND finalized_at IS NOT NULL)
           )
         ) STRICT;
         CREATE TABLE IF NOT EXISTS trusted_time_watermark (
           singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
           observed_at TEXT NOT NULL
         ) STRICT;
         PRAGMA application_id = 1129467973;
         PRAGMA user_version = 3;
         COMMIT;",
    )?;
    verify(connection)
}

fn verify(connection: &Connection) -> Result<()> {
    let expected_attempts = "CREATE TABLE enforcement_attempts (
      command_jti TEXT PRIMARY KEY,
      reservation_id TEXT NOT NULL UNIQUE,
      command_digest TEXT NOT NULL,
      outcome TEXT NOT NULL CHECK(outcome IN (
        'reserved', 'applied', 'rejected', 'failed', 'partial'
      )),
      receipt_json TEXT,
      reserved_at TEXT NOT NULL,
      finalized_at TEXT,
      CHECK(
        (outcome = 'reserved' AND receipt_json IS NULL AND finalized_at IS NULL)
        OR
        (outcome != 'reserved' AND receipt_json IS NOT NULL AND finalized_at IS NOT NULL)
      )
    ) STRICT";
    let mut statement = connection.prepare(
        "SELECT name, sql FROM sqlite_schema
         WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let actual = rows.collect::<std::result::Result<Vec<_>, _>>()?;
    let expected_time = "CREATE TABLE trusted_time_watermark (
      singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
      observed_at TEXT NOT NULL
    ) STRICT";
    if actual.len() != 2
        || actual[0].0 != "enforcement_attempts"
        || normalized(&actual[0].1) != normalized(expected_attempts)
        || actual[1].0 != "trusted_time_watermark"
        || normalized(&actual[1].1) != normalized(expected_time)
    {
        return Err(PepError::LedgerIntegrity);
    }
    Ok(())
}

fn normalized(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}
