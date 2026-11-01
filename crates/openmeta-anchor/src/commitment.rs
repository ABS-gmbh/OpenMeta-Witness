use openmeta_core::{Digest, Timestamp};
use openmeta_log::SignedCheckpoint;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AnchorError {
    #[error(
        "log {log_id} already anchored root {anchored} for size {size}; refusing conflicting root {offered}"
    )]
    Conflict {
        log_id: Digest,
        size: u64,
        anchored: Digest,
        offered: Digest,
    },
    #[error("log {log_id} already anchored size {latest}; size {offered} would move backwards")]
    SizeRegression {
        log_id: Digest,
        latest: u64,
        offered: u64,
    },
    #[error("ledger I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("ledger entry is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("ledger integrity check failed: {0}")]
    Corrupted(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorCommitment {
    pub log_id: Digest,
    pub tree_size: u64,
    pub root: Digest,
    pub checkpoint_hash: Digest,
}

impl AnchorCommitment {
    pub fn from_checkpoint(checkpoint: &SignedCheckpoint) -> Self {
        Self {
            log_id: checkpoint.checkpoint.log_id,
            tree_size: checkpoint.checkpoint.size,
            root: checkpoint.checkpoint.root,
            checkpoint_hash: checkpoint.hash(),
        }
    }

    pub fn to_bytes(&self) -> [u8; 104] {
        let mut bytes = [0u8; 104];
        bytes[..32].copy_from_slice(self.log_id.as_bytes());
        bytes[32..40].copy_from_slice(&self.tree_size.to_be_bytes());
        bytes[40..72].copy_from_slice(self.root.as_bytes());
        bytes[72..].copy_from_slice(self.checkpoint_hash.as_bytes());
        bytes
    }

    pub fn id(&self) -> Digest {
        Digest::tagged("openmeta/anchor-commitment/v1", &self.to_bytes())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorReceipt {
    pub backend: String,
    pub height: u64,
    pub block_hash: Digest,
    pub anchored_at: Timestamp,
    pub commitment: AnchorCommitment,
}

pub trait AnchorBackend {
    fn submit(
        &mut self,
        commitment: &AnchorCommitment,
        at: Timestamp,
    ) -> Result<AnchorReceipt, AnchorError>;

    fn lookup(&self, log_id: &Digest, tree_size: u64)
    -> Result<Option<AnchorReceipt>, AnchorError>;
}

#[derive(Debug, PartialEq, Eq)]
pub enum AnchorStatus {
    Anchored(AnchorReceipt),
    NotAnchored,
    Conflict(AnchorReceipt),
}

pub fn check_anchor(
    backend: &impl AnchorBackend,
    checkpoint: &SignedCheckpoint,
) -> Result<AnchorStatus, AnchorError> {
    let cp = &checkpoint.checkpoint;
    Ok(match backend.lookup(&cp.log_id, cp.size)? {
        None => AnchorStatus::NotAnchored,
        Some(receipt) if receipt.commitment.root == cp.root => AnchorStatus::Anchored(receipt),
        Some(receipt) => AnchorStatus::Conflict(receipt),
    })
}
