use std::path::{Path, PathBuf};

use openmeta_core::{PublicKey, SignedRecord};
use openmeta_log::{PublicationLog, SignedCheckpoint, record_leaf};
use rusqlite::{Connection, OptionalExtension, params};

use crate::StoreError;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS log_config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    operator_name TEXT NOT NULL,
    operator_key TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS entries (
    idx INTEGER PRIMARY KEY,
    purl TEXT NOT NULL,
    revision INTEGER NOT NULL,
    content_hash TEXT NOT NULL,
    leaf_hash TEXT NOT NULL,
    record TEXT NOT NULL,
    UNIQUE (purl, revision)
);
CREATE TABLE IF NOT EXISTS checkpoints (
    size INTEGER PRIMARY KEY,
    root TEXT NOT NULL,
    checkpoint TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS entries_no_update BEFORE UPDATE ON entries
BEGIN SELECT RAISE(ABORT, 'publication log entries are append-only'); END;
CREATE TRIGGER IF NOT EXISTS entries_no_delete BEFORE DELETE ON entries
BEGIN SELECT RAISE(ABORT, 'publication log entries are append-only'); END;
CREATE TRIGGER IF NOT EXISTS checkpoints_no_update BEFORE UPDATE ON checkpoints
BEGIN SELECT RAISE(ABORT, 'checkpoints are append-only'); END;
CREATE TRIGGER IF NOT EXISTS checkpoints_no_delete BEFORE DELETE ON checkpoints
BEGIN SELECT RAISE(ABORT, 'checkpoints are append-only'); END;
";

pub struct LogStore {
    conn: Connection,
    path: PathBuf,
}

impl LogStore {
    fn connect(path: &Path) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            conn,
            path: path.to_path_buf(),
        })
    }

    pub fn create(
        path: impl AsRef<Path>,
        operator_name: &str,
        operator_key: &PublicKey,
    ) -> Result<Self, StoreError> {
        let store = Self::connect(path.as_ref())?;
        let inserted = store.conn.execute(
            "INSERT OR IGNORE INTO log_config (id, operator_name, operator_key) VALUES (1, ?1, ?2)",
            params![operator_name, operator_key.to_string()],
        )?;
        if inserted == 0 {
            return Err(StoreError::AlreadyInitialized(store.path));
        }
        Ok(store)
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(StoreError::NotInitialized(path.to_path_buf()));
        }
        let store = Self::connect(path)?;
        store.operator()?;
        Ok(store)
    }

    pub fn operator(&self) -> Result<(String, PublicKey), StoreError> {
        let row: Option<(String, String)> = self
            .conn
            .query_row(
                "SELECT operator_name, operator_key FROM log_config WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (name, key) = row.ok_or_else(|| StoreError::NotInitialized(self.path.clone()))?;
        Ok((name, key.parse()?))
    }

    pub fn load(&self) -> Result<PublicationLog, StoreError> {
        let (_, operator) = self.operator()?;
        let mut log = PublicationLog::new(operator);
        let mut stmt = self
            .conn
            .prepare("SELECT idx, leaf_hash, record FROM entries ORDER BY idx")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, u64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        for row in rows {
            let (idx, leaf, json) = row?;
            if idx != log.size() {
                return Err(StoreError::Corrupted(format!(
                    "entry index {idx} found where {} was expected",
                    log.size()
                )));
            }
            let record: SignedRecord = serde_json::from_str(&json)?;
            if record_leaf(&record).to_string() != leaf {
                return Err(StoreError::Corrupted(format!(
                    "entry {idx} does not match its stored leaf hash"
                )));
            }
            log.append(record).map_err(|e| {
                StoreError::Corrupted(format!("entry {idx} cannot be replayed: {e}"))
            })?;
        }
        for checkpoint in self.checkpoints()? {
            log.verify_checkpoint(&checkpoint).map_err(|e| {
                StoreError::Corrupted(format!(
                    "stored checkpoint for size {}: {e}",
                    checkpoint.checkpoint.size
                ))
            })?;
        }
        Ok(log)
    }

    pub fn append(
        &self,
        log: &mut PublicationLog,
        record: SignedRecord,
    ) -> Result<u64, StoreError> {
        log.check_append(&record)?;
        let index = log.size();
        self.conn.execute(
            "INSERT INTO entries (idx, purl, revision, content_hash, leaf_hash, record)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                index,
                record.metadata.purl.to_string(),
                record.metadata.revision,
                record.content_hash().to_string(),
                record_leaf(&record).to_string(),
                String::from_utf8(record.canonical_bytes())
                    .map_err(|e| StoreError::Corrupted(e.to_string()))?,
            ],
        )?;
        Ok(log.append(record)?)
    }

    pub fn save_checkpoint(
        &self,
        log: &PublicationLog,
        checkpoint: &SignedCheckpoint,
    ) -> Result<(), StoreError> {
        log.verify_checkpoint(checkpoint)?;
        if let Some(existing) = self.checkpoint(checkpoint.checkpoint.size)? {
            if existing.checkpoint.root != checkpoint.checkpoint.root {
                return Err(StoreError::ConflictingCheckpoint(
                    checkpoint.checkpoint.size,
                ));
            }
            return Ok(());
        }
        self.conn.execute(
            "INSERT INTO checkpoints (size, root, checkpoint) VALUES (?1, ?2, ?3)",
            params![
                checkpoint.checkpoint.size,
                checkpoint.checkpoint.root.to_string(),
                serde_json::to_string(checkpoint)?,
            ],
        )?;
        Ok(())
    }

    pub fn checkpoint(&self, size: u64) -> Result<Option<SignedCheckpoint>, StoreError> {
        let json: Option<String> = self
            .conn
            .query_row(
                "SELECT checkpoint FROM checkpoints WHERE size = ?1",
                [size],
                |row| row.get(0),
            )
            .optional()?;
        json.map(|j| serde_json::from_str(&j).map_err(StoreError::from))
            .transpose()
    }

    pub fn latest_checkpoint(&self) -> Result<Option<SignedCheckpoint>, StoreError> {
        Ok(self.checkpoints()?.pop())
    }

    pub fn checkpoints(&self) -> Result<Vec<SignedCheckpoint>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT checkpoint FROM checkpoints ORDER BY size")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        rows.map(|json| Ok(serde_json::from_str(&json?)?)).collect()
    }
}
