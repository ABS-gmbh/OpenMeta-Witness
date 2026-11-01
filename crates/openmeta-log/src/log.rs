use std::collections::HashMap;

use openmeta_core::{Digest, Keypair, PublicKey, Purl, SignedRecord, Timestamp};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::checkpoint::{Checkpoint, CheckpointError, SignedCheckpoint};
use crate::merkle::{ConsistencyProof, InclusionProof, MerkleTree, ProofError, leaf_hash};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LogError {
    #[error("invalid record: {0}")]
    InvalidRecord(#[from] openmeta_core::Error),
    #[error("publisher name `{0}` is already bound to a different key")]
    PublisherKeyConflict(String),
    #[error("package {package} is owned by a different publisher key (fingerprint {owner})")]
    NotPackageOwner { package: String, owner: Digest },
    #[error(
        "{purl} revision {revision} would overwrite published history; corrections must be published as revision {expected}"
    )]
    Overwrite {
        purl: String,
        revision: u32,
        expected: u32,
    },
    #[error("{purl}: expected revision {expected}, got {actual}")]
    UnexpectedRevision {
        purl: String,
        expected: u32,
        actual: u32,
    },
    #[error("{purl}: revision {revision} does not reference the current head {head}")]
    BrokenRevisionChain {
        purl: String,
        revision: u32,
        head: Digest,
    },
    #[error("checkpoints must be signed by the log operator key")]
    NotOperator,
    #[error("record {0} does not exist")]
    UnknownRecord(u64),
    #[error("checkpoint for size {size} commits to root {claimed}, but the log root is {actual}")]
    CheckpointMismatch {
        size: u64,
        claimed: Digest,
        actual: Digest,
    },
    #[error("inclusion proof is for tree size {proof}, checkpoint has size {checkpoint}")]
    ProofSizeMismatch { proof: u64, checkpoint: u64 },
    #[error(transparent)]
    Checkpoint(#[from] CheckpointError),
    #[error(transparent)]
    Proof(#[from] ProofError),
}

pub fn record_leaf(record: &SignedRecord) -> Digest {
    leaf_hash(&record.canonical_bytes())
}

#[derive(Clone, Copy, Debug)]
struct RevisionHead {
    revision: u32,
    hash: Digest,
}

#[derive(Clone, Debug)]
pub struct PublicationLog {
    operator: PublicKey,
    records: Vec<SignedRecord>,
    tree: MerkleTree,
    publishers: HashMap<String, PublicKey>,
    owners: HashMap<Purl, PublicKey>,
    heads: HashMap<Purl, RevisionHead>,
}

impl PublicationLog {
    pub fn new(operator: PublicKey) -> Self {
        Self {
            operator,
            records: Vec::new(),
            tree: MerkleTree::new(),
            publishers: HashMap::new(),
            owners: HashMap::new(),
            heads: HashMap::new(),
        }
    }

    pub fn from_records(
        operator: PublicKey,
        records: impl IntoIterator<Item = SignedRecord>,
    ) -> Result<Self, LogError> {
        let mut log = Self::new(operator);
        for record in records {
            log.append(record)?;
        }
        Ok(log)
    }

    pub fn log_id(&self) -> Digest {
        self.operator.fingerprint()
    }

    pub fn operator(&self) -> &PublicKey {
        &self.operator
    }

    pub fn size(&self) -> u64 {
        self.tree.size()
    }

    pub fn root(&self) -> Digest {
        self.tree.root()
    }

    pub fn root_at(&self, size: u64) -> Result<Digest, LogError> {
        Ok(self.tree.root_at(size)?)
    }

    pub fn records(&self) -> &[SignedRecord] {
        &self.records
    }

    pub fn record(&self, index: u64) -> Result<&SignedRecord, LogError> {
        self.records
            .get(index as usize)
            .ok_or(LogError::UnknownRecord(index))
    }

    pub fn leaf(&self, index: u64) -> Result<Digest, LogError> {
        self.tree.leaf(index).ok_or(LogError::UnknownRecord(index))
    }

    pub fn history(&self, purl: &Purl) -> Vec<(u64, &SignedRecord)> {
        self.records
            .iter()
            .enumerate()
            .filter(|(_, r)| &r.metadata.purl == purl)
            .map(|(i, r)| (i as u64, r))
            .collect()
    }

    pub fn next_revision(&self, purl: &Purl) -> (u32, Option<Digest>) {
        match self.heads.get(purl) {
            Some(head) => (head.revision + 1, Some(head.hash)),
            None => (1, None),
        }
    }

    pub fn check_append(&self, record: &SignedRecord) -> Result<(), LogError> {
        record.verify()?;
        let metadata = &record.metadata;
        let publisher_key = metadata.publisher.public_key;

        if let Some(bound) = self.publishers.get(&metadata.publisher.name)
            && *bound != publisher_key
        {
            return Err(LogError::PublisherKeyConflict(
                metadata.publisher.name.clone(),
            ));
        }

        let package = metadata.purl.without_version();
        if let Some(owner) = self.owners.get(&package)
            && *owner != publisher_key
        {
            return Err(LogError::NotPackageOwner {
                package: package.to_string(),
                owner: owner.fingerprint(),
            });
        }

        let purl = &metadata.purl;
        match self.heads.get(purl) {
            None if metadata.revision == 1 => Ok(()),
            None => Err(LogError::UnexpectedRevision {
                purl: purl.to_string(),
                expected: 1,
                actual: metadata.revision,
            }),
            Some(head) if metadata.revision <= head.revision => Err(LogError::Overwrite {
                purl: purl.to_string(),
                revision: metadata.revision,
                expected: head.revision + 1,
            }),
            Some(head) if metadata.revision != head.revision + 1 => {
                Err(LogError::UnexpectedRevision {
                    purl: purl.to_string(),
                    expected: head.revision + 1,
                    actual: metadata.revision,
                })
            }
            Some(head) if metadata.previous_revision != Some(head.hash) => {
                Err(LogError::BrokenRevisionChain {
                    purl: purl.to_string(),
                    revision: metadata.revision,
                    head: head.hash,
                })
            }
            Some(_) => Ok(()),
        }
    }

    pub fn append(&mut self, record: SignedRecord) -> Result<u64, LogError> {
        self.check_append(&record)?;
        let metadata = &record.metadata;
        let publisher_key = metadata.publisher.public_key;
        self.publishers
            .insert(metadata.publisher.name.clone(), publisher_key);
        self.owners
            .insert(metadata.purl.without_version(), publisher_key);
        self.heads.insert(
            metadata.purl.clone(),
            RevisionHead {
                revision: metadata.revision,
                hash: record.content_hash(),
            },
        );
        let index = self.tree.push(record_leaf(&record));
        self.records.push(record);
        Ok(index)
    }

    pub fn checkpoint(
        &self,
        key: &Keypair,
        timestamp: Timestamp,
    ) -> Result<SignedCheckpoint, LogError> {
        if key.public_key() != self.operator {
            return Err(LogError::NotOperator);
        }
        Ok(Checkpoint {
            log_id: self.log_id(),
            size: self.size(),
            root: self.root(),
            timestamp,
        }
        .sign(key))
    }

    pub fn verify_checkpoint(&self, checkpoint: &SignedCheckpoint) -> Result<(), LogError> {
        checkpoint.verify(&self.operator)?;
        let size = checkpoint.checkpoint.size;
        let actual = self.root_at(size)?;
        if actual != checkpoint.checkpoint.root {
            return Err(LogError::CheckpointMismatch {
                size,
                claimed: checkpoint.checkpoint.root,
                actual,
            });
        }
        Ok(())
    }

    pub fn inclusion_proof(&self, index: u64, size: u64) -> Result<InclusionProof, LogError> {
        Ok(self.tree.inclusion_proof(index, size)?)
    }

    pub fn consistency_proof(&self, old: u64, new: u64) -> Result<ConsistencyProof, LogError> {
        Ok(self.tree.consistency_proof(old, new)?)
    }

    pub fn record_proof(
        &self,
        index: u64,
        checkpoint: &SignedCheckpoint,
    ) -> Result<RecordProof, LogError> {
        self.verify_checkpoint(checkpoint)?;
        Ok(RecordProof {
            record: self.record(index)?.clone(),
            proof: self.inclusion_proof(index, checkpoint.checkpoint.size)?,
            checkpoint: checkpoint.clone(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordProof {
    pub record: SignedRecord,
    pub proof: InclusionProof,
    pub checkpoint: SignedCheckpoint,
}

impl RecordProof {
    pub fn verify(
        &self,
        log_key: &PublicKey,
        expected_publisher: Option<&PublicKey>,
    ) -> Result<(), LogError> {
        match expected_publisher {
            Some(key) => self.record.verify_publisher(key)?,
            None => self.record.verify()?,
        }
        self.checkpoint.verify(log_key)?;
        if self.proof.tree_size != self.checkpoint.checkpoint.size {
            return Err(LogError::ProofSizeMismatch {
                proof: self.proof.tree_size,
                checkpoint: self.checkpoint.checkpoint.size,
            });
        }
        self.proof
            .verify(&record_leaf(&self.record), &self.checkpoint.checkpoint.root)?;
        Ok(())
    }
}
