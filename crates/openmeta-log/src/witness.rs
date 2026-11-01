use std::collections::BTreeMap;

use openmeta_core::{Keypair, PublicKey, SignedRecord};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::checkpoint::{
    CheckpointError, CheckpointRelation, Cosignature, EquivocationEvidence, SignedCheckpoint,
};
use crate::log::{LogError, PublicationLog};
use crate::merkle::{ConsistencyProof, ProofError};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WitnessError {
    #[error(transparent)]
    Checkpoint(#[from] CheckpointError),
    #[error(
        "equivocation: the log signed two different roots for size {}",
        .0.first.checkpoint.size
    )]
    Equivocation(Box<EquivocationEvidence>),
    #[error("checkpoint of size {new} is inconsistent with observed size {old}: {source}")]
    InconsistentHistory {
        old: u64,
        new: u64,
        source: ProofError,
    },
    #[error("checkpoint of size {offered} is older than the latest observed size {latest}")]
    Stale { offered: u64, latest: u64 },
    #[error("consistency proof covers {proof_old}->{proof_new}, expected {old}->{new}")]
    ProofSizeMismatch {
        proof_old: u64,
        proof_new: u64,
        old: u64,
        new: u64,
    },
    #[error("audit failed: {0}")]
    AuditRejected(LogError),
    #[error("audit failed: {available} records supplied for a checkpoint of size {size}")]
    AuditIncomplete { available: u64, size: u64 },
    #[error("stored observation by `{witness}` for size {size} failed verification: {source}")]
    InvalidObservation {
        witness: String,
        size: u64,
        source: CheckpointError,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub checkpoint: SignedCheckpoint,
    pub cosignature: Cosignature,
}

impl Observation {
    pub fn size(&self) -> u64 {
        self.checkpoint.checkpoint.size
    }

    pub fn verify(&self, log_key: &PublicKey) -> Result<(), WitnessError> {
        let invalid = |source| WitnessError::InvalidObservation {
            witness: self.cosignature.witness.clone(),
            size: self.size(),
            source,
        };
        self.checkpoint.verify(log_key).map_err(invalid)?;
        self.cosignature.verify(&self.checkpoint).map_err(invalid)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ObserveOutcome {
    Accepted(Box<Observation>),
    AlreadyObserved,
}

#[derive(Debug)]
pub struct Witness {
    name: String,
    key: Keypair,
    log_key: PublicKey,
    observations: BTreeMap<u64, Observation>,
}

impl Witness {
    pub fn new(name: impl Into<String>, key: Keypair, log_key: PublicKey) -> Self {
        Self {
            name: name.into(),
            key,
            log_key,
            observations: BTreeMap::new(),
        }
    }

    pub fn restore(
        name: impl Into<String>,
        key: Keypair,
        log_key: PublicKey,
        observations: impl IntoIterator<Item = Observation>,
    ) -> Result<Self, WitnessError> {
        let mut witness = Self::new(name, key, log_key);
        for observation in observations {
            observation.verify(&witness.log_key)?;
            if observation.cosignature.witness_key != witness.key.public_key() {
                return Err(WitnessError::InvalidObservation {
                    witness: witness.name.clone(),
                    size: observation.size(),
                    source: CheckpointError::InvalidCosignature,
                });
            }
            witness.observations.insert(observation.size(), observation);
        }
        Ok(witness)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn public_key(&self) -> PublicKey {
        self.key.public_key()
    }

    pub fn log_key(&self) -> &PublicKey {
        &self.log_key
    }

    pub fn latest(&self) -> Option<&Observation> {
        self.observations.values().next_back()
    }

    pub fn latest_size(&self) -> u64 {
        self.latest().map_or(0, Observation::size)
    }

    pub fn observations(&self) -> impl Iterator<Item = &Observation> {
        self.observations.values()
    }

    pub fn observe(
        &mut self,
        checkpoint: SignedCheckpoint,
        proof: &ConsistencyProof,
    ) -> Result<ObserveOutcome, WitnessError> {
        checkpoint.verify(&self.log_key)?;
        let size = checkpoint.checkpoint.size;

        if let Some(seen) = self.observations.get(&size) {
            return match seen.checkpoint.compare(&checkpoint) {
                CheckpointRelation::Equivocation => {
                    let evidence = EquivocationEvidence::new(
                        seen.checkpoint.clone(),
                        checkpoint,
                        &self.log_key,
                    )?;
                    Err(WitnessError::Equivocation(Box::new(evidence)))
                }
                _ => Ok(ObserveOutcome::AlreadyObserved),
            };
        }

        if let Some(latest) = self.latest() {
            let old = latest.size();
            if size < old {
                return Err(WitnessError::Stale {
                    offered: size,
                    latest: old,
                });
            }
            if proof.old_size != old || proof.new_size != size {
                return Err(WitnessError::ProofSizeMismatch {
                    proof_old: proof.old_size,
                    proof_new: proof.new_size,
                    old,
                    new: size,
                });
            }
            proof
                .verify(
                    &latest.checkpoint.checkpoint.root,
                    &checkpoint.checkpoint.root,
                )
                .map_err(|source| WitnessError::InconsistentHistory {
                    old,
                    new: size,
                    source,
                })?;
        }

        let observation = Observation {
            cosignature: Cosignature::create(&self.name, &self.key, &checkpoint),
            checkpoint,
        };
        self.observations.insert(size, observation.clone());
        Ok(ObserveOutcome::Accepted(Box::new(observation)))
    }

    pub fn audit(
        &self,
        checkpoint: &SignedCheckpoint,
        records: &[SignedRecord],
    ) -> Result<(), WitnessError> {
        checkpoint.verify(&self.log_key)?;
        let size = checkpoint.checkpoint.size;
        if (records.len() as u64) < size {
            return Err(WitnessError::AuditIncomplete {
                available: records.len() as u64,
                size,
            });
        }
        let replayed =
            PublicationLog::from_records(self.log_key, records[..size as usize].iter().cloned())
                .map_err(WitnessError::AuditRejected)?;
        replayed
            .verify_checkpoint(checkpoint)
            .map_err(WitnessError::AuditRejected)
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ComparisonReport {
    pub agreed: Vec<u64>,
    pub conflicts: Vec<EquivocationEvidence>,
    pub only_first: Vec<u64>,
    pub only_second: Vec<u64>,
}

impl ComparisonReport {
    pub fn is_consistent(&self) -> bool {
        self.conflicts.is_empty()
    }
}

pub fn compare_observations(
    log_key: &PublicKey,
    first: &[Observation],
    second: &[Observation],
) -> Result<ComparisonReport, WitnessError> {
    let index = |observations: &[Observation]| -> Result<BTreeMap<u64, Observation>, WitnessError> {
        observations
            .iter()
            .map(|o| o.verify(log_key).map(|()| (o.size(), o.clone())))
            .collect()
    };
    let first = index(first)?;
    let second = index(second)?;

    let mut report = ComparisonReport::default();
    for (size, a) in &first {
        match second.get(size) {
            None => report.only_first.push(*size),
            Some(b) => match a.checkpoint.compare(&b.checkpoint) {
                CheckpointRelation::Equivocation => report.conflicts.push(
                    EquivocationEvidence::new(a.checkpoint.clone(), b.checkpoint.clone(), log_key)?,
                ),
                _ => report.agreed.push(*size),
            },
        }
    }
    report.only_second = second
        .keys()
        .filter(|size| !first.contains_key(size))
        .copied()
        .collect();
    Ok(report)
}
