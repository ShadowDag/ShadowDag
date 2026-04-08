// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Database Migrations — Schema version tracking and automatic upgrades.
//
// Each migration has a version number and a description. On startup,
// the node checks the current DB version and applies any pending
// migrations in order.
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::DB;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::errors::StorageError;
use crate::{slog_info, slog_error};

/// Current database schema version
pub const CURRENT_DB_VERSION: u32 = 6;

/// Migration key in the database
const DB_VERSION_KEY: &[u8] = b"__db_schema_version__";
const MIGRATION_LOG_PREFIX: &str = "migration:";

/// A single migration step
#[derive(Debug, Clone)]
pub struct Migration {
    pub version:     u32,
    pub description: String,
    pub applied_at:  Option<u64>,
}

/// Migration result
#[derive(Debug)]
pub enum MigrationResult {
    AlreadyUpToDate,
    Applied { from: u32, to: u32, count: usize },
    Error(String),
}

/// Database migration manager
pub struct MigrationManager;

impl MigrationManager {
    /// Get the current schema version from the database
    pub fn get_version(db: &DB) -> u32 {
        match db.get(DB_VERSION_KEY) {
            Ok(Some(data)) if data.len() >= 4 => {
                let mut arr = [0u8; 4];
                arr.copy_from_slice(&data[..4]);
                u32::from_le_bytes(arr)
            }
            _ => 0, // No version = fresh database
        }
    }

    /// Set the schema version
    pub fn set_version(db: &DB, version: u32) -> Result<(), StorageError> {
        db.put(DB_VERSION_KEY, version.to_le_bytes())?;
        Ok(())
    }

    /// Check if migrations are needed
    pub fn needs_migration(db: &DB) -> bool {
        Self::get_version(db) < CURRENT_DB_VERSION
    }

    /// Run all pending migrations
    pub fn migrate(db: &DB) -> MigrationResult {
        let current = Self::get_version(db);

        if current > CURRENT_DB_VERSION {
            return MigrationResult::Error(format!(
                "DB version {} is newer than software version {}",
                current, CURRENT_DB_VERSION
            ));
        }

        if current == CURRENT_DB_VERSION {
            return MigrationResult::AlreadyUpToDate;
        }

        let mut applied = 0;

        for version in (current + 1)..=CURRENT_DB_VERSION {
            match Self::apply_migration(db, version) {
                Ok(_) => {
                    Self::log_migration(db, version);
                    applied += 1;
                    slog_info!("storage", "migration_applied", version => version, description => Self::migration_description(version));
                }
                Err(e) => {
                    return MigrationResult::Error(format!(
                        "Migration v{} failed: {}", version, e
                    ));
                }
            }
        }

        if let Err(e) = Self::set_version(db, CURRENT_DB_VERSION) {
            return MigrationResult::Error(e.to_string());
        }

        MigrationResult::Applied {
            from: current,
            to: CURRENT_DB_VERSION,
            count: applied,
        }
    }

    /// Apply a specific migration version.
    ///
    /// All current migrations are schema-only: they declare a new key prefix
    /// or index that is lazily created on first use by the owning subsystem.
    /// No data transformation is performed at migration time.
    fn apply_migration(_db: &DB, version: u32) -> Result<(), StorageError> {
        match version {
            1 => Ok(()), // Schema: initial DB layout — no data migration needed
            2 => Ok(()), // Schema: UTXO address index — created on first use by UtxoStore
            3 => Ok(()), // Schema: DAG blue score index — populated by GhostDag on block insert
            4 => Ok(()), // Schema: contract state prefix — created on first contract deploy
            5 => Ok(()), // Schema: BPS configuration key — written on first config update
            6 => Ok(()), // Schema: pruning metadata + UTXO commitments — populated by pruning manager
            _ => Err(StorageError::Migration(format!("Unknown migration version: {}", version))),
        }
    }

    /// Get migration description
    fn migration_description(version: u32) -> &'static str {
        match version {
            1 => "Initial database schema",
            2 => "Add UTXO address index",
            3 => "Add DAG blue score index",
            4 => "Add contract state storage",
            5 => "Add BPS configuration storage",
            6 => "Add pruning metadata and UTXO commitments",
            _ => "Unknown migration",
        }
    }

    /// Log migration application
    fn log_migration(db: &DB, version: u32) {
        let key = format!("{}{}", MIGRATION_LOG_PREFIX, version);
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        if let Err(e) = db.put(key.as_bytes(), ts.to_le_bytes()) {
            slog_error!("storage", "migration_log_write_failed", version => version, error => e);
        }
    }

    /// Get all applied migrations
    pub fn get_history(db: &DB) -> Vec<Migration> {
        let mut history = Vec::new();
        for version in 1..=CURRENT_DB_VERSION {
            let key = format!("{}{}", MIGRATION_LOG_PREFIX, version);
            let applied_at = db.get(key.as_bytes()).ok().flatten().map(|data| {
                if data.len() >= 8 {
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(&data[..8]);
                    u64::from_le_bytes(arr)
                } else { 0 }
            });
            history.push(Migration {
                version,
                description: Self::migration_description(version).to_string(),
                applied_at,
            });
        }
        history
    }

    /// Verify database integrity
    pub fn verify(db: &DB) -> Result<(), StorageError> {
        let version = Self::get_version(db);
        if version > CURRENT_DB_VERSION {
            return Err(StorageError::Migration(format!(
                "Database version {} is ahead of software version {}. Upgrade required.",
                version, CURRENT_DB_VERSION
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocksdb::Options;

    fn make_db() -> DB {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let path = format!("/tmp/test_migrations_{}", ts);
        let mut opts = Options::default();
        opts.create_if_missing(true);
        DB::open(&opts, &path).unwrap()
    }

    #[test]
    fn fresh_db_version_is_zero() {
        let db = make_db();
        assert_eq!(MigrationManager::get_version(&db), 0);
    }

    #[test]
    fn needs_migration_on_fresh() {
        let db = make_db();
        assert!(MigrationManager::needs_migration(&db));
    }

    #[test]
    fn migrate_applies_all() {
        let db = make_db();
        match MigrationManager::migrate(&db) {
            MigrationResult::Applied { from, to, count } => {
                assert_eq!(from, 0);
                assert_eq!(to, CURRENT_DB_VERSION);
                assert_eq!(count, CURRENT_DB_VERSION as usize);
            }
            _ => panic!("Expected Applied"),
        }
        assert_eq!(MigrationManager::get_version(&db), CURRENT_DB_VERSION);
    }

    #[test]
    fn already_up_to_date() {
        let db = make_db();
        MigrationManager::migrate(&db);
        match MigrationManager::migrate(&db) {
            MigrationResult::AlreadyUpToDate => {}
            _ => panic!("Expected AlreadyUpToDate"),
        }
    }

    #[test]
    fn history_shows_all() {
        let db = make_db();
        MigrationManager::migrate(&db);
        let history = MigrationManager::get_history(&db);
        assert_eq!(history.len(), CURRENT_DB_VERSION as usize);
        assert!(history.iter().all(|m| m.applied_at.is_some()));
    }

    #[test]
    fn verify_passes_after_migration() {
        let db = make_db();
        MigrationManager::migrate(&db);
        assert!(MigrationManager::verify(&db).is_ok());
    }
}
