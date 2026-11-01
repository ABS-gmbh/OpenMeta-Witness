use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("stored JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Core(#[from] openmeta_core::Error),
    #[error(transparent)]
    Log(#[from] openmeta_log::LogError),
    #[error(transparent)]
    Witness(#[from] openmeta_log::WitnessError),
    #[error("{0} is not initialized")]
    NotInitialized(PathBuf),
    #[error("{0} is already initialized")]
    AlreadyInitialized(PathBuf),
    #[error("key `{0}` already exists")]
    KeyExists(String),
    #[error("key `{0}` was not found")]
    KeyNotFound(String),
    #[error("invalid key name `{0}`: use lowercase letters, digits, `-` or `_`")]
    InvalidKeyName(String),
    #[error("stored data failed integrity verification: {0}")]
    Corrupted(String),
    #[error("a different checkpoint for size {0} is already stored")]
    ConflictingCheckpoint(u64),
}
