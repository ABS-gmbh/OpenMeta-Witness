use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use openmeta_anchor::LocalLedger;
use openmeta_core::{
    DependencyRef, Digest, License, PackageMetadata, PublisherIdentity, Purl, SignedRecord,
    SourceReference, Timestamp, VulnerabilityRef,
};
use openmeta_log::{
    ComparisonReport, Observation, ObserveOutcome, PublicationLog, SignedCheckpoint, WitnessError,
    compare_observations,
};
use openmeta_store::{Keystore, LogStore, WitnessStore};

pub struct Draft {
    pub purl: Purl,
    pub repository: String,
    pub source_revision: String,
    pub artifact_digest: Digest,
    pub license: String,
    pub dependencies: Vec<DependencyRef>,
    pub vulnerabilities: Vec<VulnerabilityRef>,
    pub published_at: Timestamp,
}

impl Draft {
    pub fn into_metadata(
        self,
        publisher: PublisherIdentity,
        log: &PublicationLog,
    ) -> Result<PackageMetadata> {
        let version = self
            .purl
            .version()
            .ok_or_else(|| anyhow!("package URL {} must include a version", self.purl))?
            .to_string();
        let (revision, previous_revision) = log.next_revision(&self.purl);
        Ok(PackageMetadata {
            name: self.purl.name().to_string(),
            version,
            source: SourceReference {
                repository: self.repository,
                revision: self.source_revision,
            },
            artifact_digest: self.artifact_digest,
            publisher,
            published_at: self.published_at,
            license: License {
                spdx_expression: self.license,
            },
            dependencies: self.dependencies,
            vulnerabilities: self.vulnerabilities,
            revision,
            previous_revision,
            purl: self.purl,
        })
    }
}

pub enum Verdict {
    Accepted(Box<Observation>),
    AlreadyObserved,
    Rejected(WitnessError),
}

pub struct Workspace {
    root: PathBuf,
    keys: Keystore,
}

impl Workspace {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let keys = Keystore::open(root.join("keys"))
            .with_context(|| format!("opening key store in {}", root.display()))?;
        Ok(Self { root, keys })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn keys(&self) -> &Keystore {
        &self.keys
    }

    fn log_path(&self) -> PathBuf {
        self.root.join("log.db")
    }

    fn witness_path(&self, name: &str) -> PathBuf {
        self.root.join("witnesses").join(format!("{name}.db"))
    }

    pub fn ledger_path(&self) -> PathBuf {
        self.root.join("anchors").join("ledger.jsonl")
    }

    pub fn init_log(&self, operator: &str) -> Result<LogStore> {
        let key = self.keys.public_key(operator)?;
        Ok(LogStore::create(self.log_path(), operator, &key)?)
    }

    pub fn log_store(&self) -> Result<LogStore> {
        LogStore::open(self.log_path())
            .context("no publication log here; run `openmeta log init` first")
    }

    pub fn load_log(&self) -> Result<(LogStore, PublicationLog)> {
        let store = self.log_store()?;
        let log = store.load()?;
        Ok((store, log))
    }

    pub fn latest_checkpoint(&self) -> Result<SignedCheckpoint> {
        self.log_store()?.latest_checkpoint()?.ok_or_else(|| {
            anyhow!("the log has no checkpoints yet; run `openmeta checkpoint create`")
        })
    }

    pub fn publish(&self, publisher: &str, draft: Draft) -> Result<(u64, SignedRecord)> {
        let key = self.keys.load(publisher)?;
        let (store, mut log) = self.load_log()?;
        let identity = PublisherIdentity {
            name: publisher.to_string(),
            public_key: key.public_key(),
        };
        let record = SignedRecord::sign(draft.into_metadata(identity, &log)?, &key)?;
        let index = store.append(&mut log, record.clone())?;
        Ok((index, record))
    }

    pub fn create_checkpoint(&self, timestamp: Timestamp) -> Result<SignedCheckpoint> {
        let (store, log) = self.load_log()?;
        let (operator, _) = store.operator()?;
        if let Some(latest) = store.latest_checkpoint()?
            && latest.checkpoint.size == log.size()
        {
            return Ok(latest);
        }
        let checkpoint = log.checkpoint(&self.keys.load(&operator)?, timestamp)?;
        store.save_checkpoint(&log, &checkpoint)?;
        Ok(checkpoint)
    }

    pub fn create_witness(&self, name: &str) -> Result<()> {
        let (_, log_key) = self.log_store()?.operator()?;
        self.keys.public_key(name)?;
        WitnessStore::create(self.witness_path(name), name, &log_key)?;
        Ok(())
    }

    pub fn witness_store(&self, name: &str) -> Result<WitnessStore> {
        WitnessStore::open(self.witness_path(name)).with_context(|| {
            format!("witness `{name}` does not exist; run `openmeta witness new {name}`")
        })
    }

    pub fn present(
        &self,
        witness_name: &str,
        source: &PublicationLog,
        checkpoint: SignedCheckpoint,
        audit: bool,
    ) -> Result<Verdict> {
        let store = self.witness_store(witness_name)?;
        let mut witness = store.load(self.keys.load(witness_name)?)?;
        if audit && let Err(e) = witness.audit(&checkpoint, source.records()) {
            return Ok(Verdict::Rejected(e));
        }
        let size = checkpoint.checkpoint.size;
        let proof = source.consistency_proof(witness.latest_size().min(size), size)?;
        Ok(match witness.observe(checkpoint, &proof) {
            Ok(ObserveOutcome::Accepted(observation)) => {
                store.add_observation(&observation)?;
                Verdict::Accepted(observation)
            }
            Ok(ObserveOutcome::AlreadyObserved) => Verdict::AlreadyObserved,
            Err(WitnessError::Equivocation(evidence)) => {
                store.add_evidence(&evidence)?;
                Verdict::Rejected(WitnessError::Equivocation(evidence))
            }
            Err(e) => Verdict::Rejected(e),
        })
    }

    pub fn observe_log(&self, witness_name: &str, audit: bool) -> Result<Verdict> {
        let checkpoint = self.latest_checkpoint()?;
        let (_, log) = self.load_log()?;
        self.present(witness_name, &log, checkpoint, audit)
    }

    pub fn compare_witnesses(&self, first: &str, second: &str) -> Result<ComparisonReport> {
        let first_store = self.witness_store(first)?;
        let second_store = self.witness_store(second)?;
        let (_, log_key) = first_store.config()?;
        if second_store.config()?.1 != log_key {
            bail!("witnesses `{first}` and `{second}` follow different logs");
        }
        let report = compare_observations(
            &log_key,
            &first_store.observations()?,
            &second_store.observations()?,
        )?;
        for evidence in &report.conflicts {
            first_store.add_evidence(evidence)?;
            second_store.add_evidence(evidence)?;
        }
        Ok(report)
    }

    pub fn ledger(&self) -> Result<LocalLedger> {
        let path = self.ledger_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Ok(LocalLedger::open(path)?)
    }
}
