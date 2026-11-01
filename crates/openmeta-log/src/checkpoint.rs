use openmeta_core::{Digest, Keypair, PublicKey, Signature, Timestamp};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const CHECKPOINT_HEADER: &str = "openmeta-checkpoint/v1";
const COSIGNATURE_HEADER: &str = "openmeta-cosignature/v1";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CheckpointError {
    #[error("checkpoint belongs to log {actual}, expected {expected}")]
    WrongLog { expected: Digest, actual: Digest },
    #[error("checkpoint signature is invalid")]
    InvalidSignature,
    #[error("cosignature is invalid")]
    InvalidCosignature,
    #[error("checkpoints are not an equivocation: {0}")]
    NotEquivocation(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub log_id: Digest,
    pub size: u64,
    pub root: Digest,
    pub timestamp: Timestamp,
}

impl Checkpoint {
    pub fn body(&self) -> String {
        format!(
            "{CHECKPOINT_HEADER}\n{}\n{}\n{}\n{}\n",
            self.log_id,
            self.size,
            self.root,
            self.timestamp.unix_seconds()
        )
    }

    pub fn sign(self, log_key: &Keypair) -> SignedCheckpoint {
        let signature = log_key.sign(self.body().as_bytes());
        SignedCheckpoint {
            checkpoint: self,
            signature,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCheckpoint {
    pub checkpoint: Checkpoint,
    pub signature: Signature,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointRelation {
    Identical,
    SameStateResigned,
    Equivocation,
    DifferentSizes,
    DifferentLogs,
}

impl SignedCheckpoint {
    pub fn verify(&self, log_key: &PublicKey) -> Result<(), CheckpointError> {
        let expected = log_key.fingerprint();
        if self.checkpoint.log_id != expected {
            return Err(CheckpointError::WrongLog {
                expected,
                actual: self.checkpoint.log_id,
            });
        }
        log_key
            .verify(self.checkpoint.body().as_bytes(), &self.signature)
            .map_err(|_| CheckpointError::InvalidSignature)
    }

    pub fn hash(&self) -> Digest {
        let mut data = self.checkpoint.body().into_bytes();
        data.extend_from_slice(self.signature.to_string().as_bytes());
        Digest::tagged("openmeta/signed-checkpoint", &data)
    }

    pub fn compare(&self, other: &SignedCheckpoint) -> CheckpointRelation {
        let (a, b) = (&self.checkpoint, &other.checkpoint);
        if a.log_id != b.log_id {
            CheckpointRelation::DifferentLogs
        } else if a.size != b.size {
            CheckpointRelation::DifferentSizes
        } else if a.root != b.root {
            CheckpointRelation::Equivocation
        } else if self == other {
            CheckpointRelation::Identical
        } else {
            CheckpointRelation::SameStateResigned
        }
    }

    pub fn cosignature_message(&self) -> Vec<u8> {
        format!("{COSIGNATURE_HEADER}\n{}", self.checkpoint.body()).into_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cosignature {
    pub witness: String,
    pub witness_key: PublicKey,
    pub signature: Signature,
}

impl Cosignature {
    pub fn create(witness: &str, key: &Keypair, checkpoint: &SignedCheckpoint) -> Self {
        Self {
            witness: witness.to_string(),
            witness_key: key.public_key(),
            signature: key.sign(&checkpoint.cosignature_message()),
        }
    }

    pub fn verify(&self, checkpoint: &SignedCheckpoint) -> Result<(), CheckpointError> {
        self.witness_key
            .verify(&checkpoint.cosignature_message(), &self.signature)
            .map_err(|_| CheckpointError::InvalidCosignature)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EquivocationEvidence {
    pub first: SignedCheckpoint,
    pub second: SignedCheckpoint,
}

impl EquivocationEvidence {
    pub fn new(
        first: SignedCheckpoint,
        second: SignedCheckpoint,
        log_key: &PublicKey,
    ) -> Result<Self, CheckpointError> {
        let evidence = Self { first, second };
        evidence.verify(log_key)?;
        Ok(evidence)
    }

    pub fn verify(&self, log_key: &PublicKey) -> Result<(), CheckpointError> {
        self.first.verify(log_key)?;
        self.second.verify(log_key)?;
        match self.first.compare(&self.second) {
            CheckpointRelation::Equivocation => Ok(()),
            CheckpointRelation::DifferentSizes => Err(CheckpointError::NotEquivocation(
                "sizes differ; a consistency proof is required",
            )),
            _ => Err(CheckpointError::NotEquivocation("roots are identical")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checkpoint(key: &Keypair, size: u64, root: &[u8]) -> SignedCheckpoint {
        Checkpoint {
            log_id: key.public_key().fingerprint(),
            size,
            root: Digest::sha256(root),
            timestamp: Timestamp::from_unix_seconds(1_767_225_600),
        }
        .sign(key)
    }

    #[test]
    fn checkpoint_signature_verifies_and_binds_fields() {
        let key = Keypair::from_seed([4; 32]);
        let cp = checkpoint(&key, 5, b"root");
        assert_eq!(cp.verify(&key.public_key()), Ok(()));

        let mut grown = cp.clone();
        grown.checkpoint.size = 6;
        assert_eq!(
            grown.verify(&key.public_key()),
            Err(CheckpointError::InvalidSignature)
        );

        let other = Keypair::from_seed([5; 32]);
        assert!(matches!(
            cp.verify(&other.public_key()),
            Err(CheckpointError::WrongLog { .. })
        ));
    }

    #[test]
    fn comparison_classifies_checkpoints() {
        let key = Keypair::from_seed([4; 32]);
        let a = checkpoint(&key, 5, b"root");
        let b = checkpoint(&key, 5, b"other root");
        let c = checkpoint(&key, 6, b"root");
        assert_eq!(a.compare(&a.clone()), CheckpointRelation::Identical);
        assert_eq!(a.compare(&b), CheckpointRelation::Equivocation);
        assert_eq!(a.compare(&c), CheckpointRelation::DifferentSizes);

        let mut later = a.checkpoint.clone();
        later.timestamp = Timestamp::from_unix_seconds(1_767_225_700);
        assert_eq!(
            a.compare(&later.sign(&key)),
            CheckpointRelation::SameStateResigned
        );
    }

    #[test]
    fn equivocation_evidence_requires_two_valid_conflicting_signatures() {
        let key = Keypair::from_seed([4; 32]);
        let a = checkpoint(&key, 5, b"root");
        let b = checkpoint(&key, 5, b"other root");
        assert!(EquivocationEvidence::new(a.clone(), b.clone(), &key.public_key()).is_ok());

        assert!(EquivocationEvidence::new(a.clone(), a.clone(), &key.public_key()).is_err());

        let mut forged = b;
        forged.signature = a.signature;
        assert_eq!(
            EquivocationEvidence::new(a, forged, &key.public_key()),
            Err(CheckpointError::InvalidSignature)
        );
    }

    #[test]
    fn cosignatures_bind_witness_to_checkpoint() {
        let log = Keypair::from_seed([4; 32]);
        let witness = Keypair::from_seed([6; 32]);
        let cp = checkpoint(&log, 5, b"root");
        let cosig = Cosignature::create("witness-a", &witness, &cp);
        assert_eq!(cosig.verify(&cp), Ok(()));
        let other = checkpoint(&log, 5, b"other");
        assert_eq!(
            cosig.verify(&other),
            Err(CheckpointError::InvalidCosignature)
        );
    }
}
