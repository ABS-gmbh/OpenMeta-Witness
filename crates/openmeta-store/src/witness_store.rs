use std::path::{Path, PathBuf};

use openmeta_core::{Keypair, PublicKey};
use openmeta_log::{EquivocationEvidence, Observation, Witness};
use rusqlite::{Connection, OptionalExtension, params};

use crate::StoreError;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS witness_config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    name TEXT NOT NULL,
    log_key TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS observations (
    size INTEGER PRIMARY KEY,
    root TEXT NOT NULL,
    observation TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    size INTEGER NOT NULL,
    evidence TEXT NOT NULL UNIQUE
);
CREATE TRIGGER IF NOT EXISTS observations_no_update BEFORE UPDATE ON observations
BEGIN SELECT RAISE(ABORT, 'witness observations are append-only'); END;
CREATE TRIGGER IF NOT EXISTS observations_no_delete BEFORE DELETE ON observations
BEGIN SELECT RAISE(ABORT, 'witness observations are append-only'); END;
";

pub struct WitnessStore {
    conn: Connection,
    path: PathBuf,
}

impl WitnessStore {
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
        name: &str,
        log_key: &PublicKey,
    ) -> Result<Self, StoreError> {
        let store = Self::connect(path.as_ref())?;
        let inserted = store.conn.execute(
            "INSERT OR IGNORE INTO witness_config (id, name, log_key) VALUES (1, ?1, ?2)",
            params![name, log_key.to_string()],
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
        store.config()?;
        Ok(store)
    }

    pub fn config(&self) -> Result<(String, PublicKey), StoreError> {
        let row: Option<(String, String)> = self
            .conn
            .query_row(
                "SELECT name, log_key FROM witness_config WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (name, key) = row.ok_or_else(|| StoreError::NotInitialized(self.path.clone()))?;
        Ok((name, key.parse()?))
    }

    pub fn load(&self, key: Keypair) -> Result<Witness, StoreError> {
        let (name, log_key) = self.config()?;
        Ok(Witness::restore(name, key, log_key, self.observations()?)?)
    }

    pub fn observations(&self) -> Result<Vec<Observation>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT observation FROM observations ORDER BY size")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        rows.map(|json| Ok(serde_json::from_str(&json?)?)).collect()
    }

    pub fn add_observation(&self, observation: &Observation) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO observations (size, root, observation) VALUES (?1, ?2, ?3)",
            params![
                observation.size(),
                observation.checkpoint.checkpoint.root.to_string(),
                serde_json::to_string(observation)?,
            ],
        )?;
        Ok(())
    }

    pub fn add_evidence(&self, evidence: &EquivocationEvidence) -> Result<bool, StoreError> {
        let inserted = self.conn.execute(
            "INSERT OR IGNORE INTO evidence (size, evidence) VALUES (?1, ?2)",
            params![
                evidence.first.checkpoint.size,
                serde_json::to_string(evidence)?
            ],
        )?;
        Ok(inserted > 0)
    }

    pub fn evidence(&self) -> Result<Vec<EquivocationEvidence>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT evidence FROM evidence ORDER BY id")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        rows.map(|json| Ok(serde_json::from_str(&json?)?)).collect()
    }
}
