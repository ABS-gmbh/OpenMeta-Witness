use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use openmeta_core::canonical::to_canonical_json;
use openmeta_core::{Digest, Timestamp};
use serde::{Deserialize, Serialize};

use crate::{AnchorBackend, AnchorCommitment, AnchorError, AnchorReceipt};

const BACKEND_NAME: &str = "local-ledger";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockHeader {
    height: u64,
    previous_hash: Digest,
    timestamp: Timestamp,
    commitment: AnchorCommitment,
}

impl BlockHeader {
    fn hash(&self) -> Digest {
        let bytes = to_canonical_json(self).expect("block headers are canonical JSON");
        Digest::tagged("openmeta/local-ledger/block", &bytes)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Block {
    header: BlockHeader,
    hash: Digest,
}

impl Block {
    fn receipt(&self) -> AnchorReceipt {
        AnchorReceipt {
            backend: BACKEND_NAME.to_string(),
            height: self.header.height,
            block_hash: self.hash,
            anchored_at: self.header.timestamp,
            commitment: self.header.commitment,
        }
    }
}

pub struct LocalLedger {
    path: PathBuf,
    blocks: Vec<Block>,
}

impl LocalLedger {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AnchorError> {
        let path = path.as_ref().to_path_buf();
        let mut blocks: Vec<Block> = Vec::new();
        if path.exists() {
            for (line_number, line) in BufReader::new(File::open(&path)?).lines().enumerate() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                let block: Block = serde_json::from_str(&line)?;
                let expected_previous = blocks
                    .last()
                    .map_or(Digest::from_bytes([0; 32]), |b| b.hash);
                if block.header.height != blocks.len() as u64
                    || block.header.previous_hash != expected_previous
                    || block.header.hash() != block.hash
                {
                    return Err(AnchorError::Corrupted(format!(
                        "block on line {} does not extend the chain",
                        line_number + 1
                    )));
                }
                blocks.push(block);
            }
        }
        Ok(Self { path, blocks })
    }

    pub fn height(&self) -> u64 {
        self.blocks.len() as u64
    }

    pub fn receipts(&self) -> impl Iterator<Item = AnchorReceipt> + '_ {
        self.blocks.iter().map(Block::receipt)
    }

    fn latest_for(&self, log_id: &Digest) -> Option<&Block> {
        self.blocks
            .iter()
            .rev()
            .find(|b| &b.header.commitment.log_id == log_id)
    }
}

impl AnchorBackend for LocalLedger {
    fn submit(
        &mut self,
        commitment: &AnchorCommitment,
        at: Timestamp,
    ) -> Result<AnchorReceipt, AnchorError> {
        if let Some(existing) = self.lookup(&commitment.log_id, commitment.tree_size)? {
            if existing.commitment.root != commitment.root {
                return Err(AnchorError::Conflict {
                    log_id: commitment.log_id,
                    size: commitment.tree_size,
                    anchored: existing.commitment.root,
                    offered: commitment.root,
                });
            }
            return Ok(existing);
        }
        if let Some(latest) = self.latest_for(&commitment.log_id) {
            let latest = latest.header.commitment.tree_size;
            if commitment.tree_size < latest {
                return Err(AnchorError::SizeRegression {
                    log_id: commitment.log_id,
                    latest,
                    offered: commitment.tree_size,
                });
            }
        }

        let header = BlockHeader {
            height: self.height(),
            previous_hash: self
                .blocks
                .last()
                .map_or(Digest::from_bytes([0; 32]), |b| b.hash),
            timestamp: at,
            commitment: *commitment,
        };
        let block = Block {
            hash: header.hash(),
            header,
        };
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{}", serde_json::to_string(&block)?)?;
        file.sync_all()?;
        let receipt = block.receipt();
        self.blocks.push(block);
        Ok(receipt)
    }

    fn lookup(
        &self,
        log_id: &Digest,
        tree_size: u64,
    ) -> Result<Option<AnchorReceipt>, AnchorError> {
        Ok(self
            .blocks
            .iter()
            .find(|b| {
                &b.header.commitment.log_id == log_id && b.header.commitment.tree_size == tree_size
            })
            .map(Block::receipt))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AnchorStatus, check_anchor};
    use openmeta_core::Keypair;
    use openmeta_log::Checkpoint;

    fn checkpoint(key: &Keypair, size: u64, root: &[u8]) -> openmeta_log::SignedCheckpoint {
        Checkpoint {
            log_id: key.public_key().fingerprint(),
            size,
            root: Digest::sha256(root),
            timestamp: Timestamp::from_unix_seconds(1_767_225_600),
        }
        .sign(key)
    }

    #[test]
    fn anchors_persist_and_chain_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.jsonl");
        let key = Keypair::from_seed([1; 32]);
        let cp = checkpoint(&key, 3, b"root");
        {
            let mut ledger = LocalLedger::open(&path).unwrap();
            let receipt = ledger
                .submit(
                    &AnchorCommitment::from_checkpoint(&cp),
                    Timestamp::from_unix_seconds(5),
                )
                .unwrap();
            assert_eq!(receipt.height, 0);
            let again = ledger
                .submit(
                    &AnchorCommitment::from_checkpoint(&cp),
                    Timestamp::from_unix_seconds(6),
                )
                .unwrap();
            assert_eq!(again, receipt);
        }
        let ledger = LocalLedger::open(&path).unwrap();
        assert_eq!(ledger.height(), 1);
        assert!(matches!(
            check_anchor(&ledger, &cp).unwrap(),
            AnchorStatus::Anchored(_)
        ));
        let later = checkpoint(&key, 4, b"later");
        assert_eq!(
            check_anchor(&ledger, &later).unwrap(),
            AnchorStatus::NotAnchored
        );
    }

    #[test]
    fn conflicting_and_regressing_commitments_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let key = Keypair::from_seed([1; 32]);
        let mut ledger = LocalLedger::open(dir.path().join("ledger.jsonl")).unwrap();
        let honest = checkpoint(&key, 3, b"root");
        let forked = checkpoint(&key, 3, b"forked root");
        ledger
            .submit(
                &AnchorCommitment::from_checkpoint(&honest),
                Timestamp::from_unix_seconds(1),
            )
            .unwrap();
        assert!(matches!(
            ledger.submit(
                &AnchorCommitment::from_checkpoint(&forked),
                Timestamp::from_unix_seconds(2)
            ),
            Err(AnchorError::Conflict { size: 3, .. })
        ));
        assert!(matches!(
            check_anchor(&ledger, &forked).unwrap(),
            AnchorStatus::Conflict(_)
        ));
        let older = checkpoint(&key, 2, b"older");
        assert!(matches!(
            ledger.submit(
                &AnchorCommitment::from_checkpoint(&older),
                Timestamp::from_unix_seconds(3)
            ),
            Err(AnchorError::SizeRegression { .. })
        ));
        assert_eq!(ledger.height(), 1);
    }

    #[test]
    fn edited_ledger_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.jsonl");
        let key = Keypair::from_seed([1; 32]);
        let mut ledger = LocalLedger::open(&path).unwrap();
        for size in 1..=3 {
            let cp = checkpoint(&key, size, &size.to_be_bytes());
            ledger
                .submit(
                    &AnchorCommitment::from_checkpoint(&cp),
                    Timestamp::from_unix_seconds(size),
                )
                .unwrap();
        }
        let original = std::fs::read_to_string(&path).unwrap();
        let replacement = Digest::sha256(b"forged root").to_string();
        let target = Digest::sha256(&2u64.to_be_bytes()).to_string();
        std::fs::write(&path, original.replace(&target, &replacement)).unwrap();
        assert!(matches!(
            LocalLedger::open(&path),
            Err(AnchorError::Corrupted(_))
        ));
    }

    #[test]
    fn commitment_is_compact_and_binds_all_fields() {
        let key = Keypair::from_seed([1; 32]);
        let a = AnchorCommitment::from_checkpoint(&checkpoint(&key, 3, b"root"));
        let b = AnchorCommitment::from_checkpoint(&checkpoint(&key, 3, b"other"));
        assert_eq!(a.to_bytes().len(), 104);
        assert_ne!(a.id(), b.id());
    }
}
