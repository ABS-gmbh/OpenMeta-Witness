use std::fs;
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Result, bail};
use openmeta_anchor::{AnchorBackend, AnchorCommitment, AnchorError};
use openmeta_core::{
    DependencyRef, Digest, Keypair, PublicKey, SignedRecord, Timestamp, VulnerabilityRef,
    VulnerabilityStatus,
};
use openmeta_log::{LogError, PublicationLog, SignedCheckpoint, WitnessError};
use openmeta_store::{LogStore, StoreError};

use crate::commands::fork_last_record;
use crate::output::{self, field, heading, info};
use crate::workspace::{Draft, Verdict, Workspace};

const MARKER: &str = ".openmeta-demo";
const T0: u64 = 1_767_225_600;
const PUBLISHER: &str = "publisher-a";
const WITNESSES: [&str; 2] = ["witness-a", "witness-b"];

fn at(offset: u64) -> Timestamp {
    Timestamp::from_unix_seconds(T0 + offset)
}

fn demo_key(name: &str) -> Keypair {
    Keypair::from_seed(*Digest::tagged("openmeta/demo-identity", name.as_bytes()).as_bytes())
}

fn prepare(dir: &Path) -> Result<()> {
    if dir.exists() {
        if dir.join(MARKER).exists() {
            fs::remove_dir_all(dir)?;
        } else if fs::read_dir(dir)?.next().is_some() {
            bail!(
                "{} exists and was not created by the demo; choose another --dir",
                dir.display()
            );
        }
    }
    fs::create_dir_all(dir)?;
    fs::write(dir.join(MARKER), "")?;
    Ok(())
}

fn examplelib(
    version: &str,
    vulnerabilities: Vec<VulnerabilityRef>,
    published_at: Timestamp,
) -> Result<Draft> {
    Ok(Draft {
        purl: format!("pkg:cargo/examplelib@{version}").parse()?,
        repository: "https://git.example.org/examplelib.git".into(),
        source_revision: format!("v{version}"),
        artifact_digest: Digest::sha256(format!("examplelib-{version}.crate").as_bytes()),
        license: "MIT OR Apache-2.0".into(),
        dependencies: vec![DependencyRef {
            purl: "pkg:cargo/serde@1.0.210".parse()?,
            requirement: Some("^1.0".into()),
        }],
        vulnerabilities,
        published_at,
    })
}

fn expect_accepted(witness: &str, observed: Verdict, audited: bool) -> Result<()> {
    match observed {
        Verdict::Accepted(observation) => {
            let cp = &observation.checkpoint.checkpoint;
            let audit = if audited {
                format!(", replayed {} record(s) and recomputed the root", cp.size)
            } else {
                String::new()
            };
            output::verified(format!(
                "{witness}: checkpoint size {} signature valid, history consistent{audit}; cosigned",
                cp.size
            ));
            Ok(())
        }
        Verdict::AlreadyObserved => {
            bail!("{witness} unexpectedly reported an already observed checkpoint")
        }
        Verdict::Rejected(e) => bail!("{witness} unexpectedly rejected the checkpoint: {e}"),
    }
}

fn expect_rejected(witness: &str, observed: Verdict) -> Result<WitnessError> {
    match observed {
        Verdict::Rejected(e) => {
            output::detected(format!("{witness} refused the checkpoint: {e}"));
            Ok(e)
        }
        _ => bail!("{witness} accepted a checkpoint it should have rejected"),
    }
}

fn expect_failure(description: &str, result: Result<(), LogError>) -> bool {
    match result {
        Err(e) => {
            output::detected(format!("{description}: {e}"));
            true
        }
        Ok(()) => {
            println!("  [MISSED]   {description}: verification unexpectedly succeeded");
            false
        }
    }
}

pub fn tampering_checks(
    log: &PublicationLog,
    checkpoint: &SignedCheckpoint,
    index: u64,
) -> Result<bool> {
    let log_key = *log.operator();
    let original = log.record_proof(index, checkpoint)?;
    let publisher: PublicKey = original.record.metadata.publisher.public_key;
    original.verify(&log_key, Some(&publisher))?;
    output::verified(format!(
        "original record #{index} verifies and is included in checkpoint size {}",
        checkpoint.checkpoint.size
    ));

    let mut detected = true;

    let mut license = original.clone();
    license.record.metadata.license.spdx_expression = "LicenseRef-Proprietary".into();
    detected &= expect_failure(
        "license changed after signing",
        license.verify(&log_key, Some(&publisher)),
    );

    let mut digest = original.clone();
    digest.record.metadata.artifact_digest = Digest::sha256(b"backdoored artifact");
    detected &= expect_failure(
        "artifact digest replaced after signing",
        digest.verify(&log_key, Some(&publisher)),
    );

    let attacker = demo_key("attacker");
    let mut metadata = original.record.metadata.clone();
    metadata.artifact_digest = Digest::sha256(b"backdoored artifact");
    metadata.publisher.public_key = attacker.public_key();
    let mut resigned = original.clone();
    resigned.record = SignedRecord::sign(metadata, &attacker)?;
    detected &= expect_failure(
        "record re-signed with an attacker key (identity check)",
        resigned.verify(&log_key, Some(&publisher)),
    );
    detected &= expect_failure(
        "record re-signed with an attacker key (inclusion check)",
        resigned.verify(&log_key, None),
    );

    let mut path = original.clone();
    if let Some(first) = path.proof.path.first_mut() {
        *first = Digest::sha256(b"forged sibling");
    } else {
        path.proof.path.push(Digest::sha256(b"forged sibling"));
    }
    detected &= expect_failure("inclusion proof path altered", path.verify(&log_key, None));

    let mut root = original;
    root.checkpoint.checkpoint.root = Digest::sha256(b"forged root");
    detected &= expect_failure("checkpoint root altered", root.verify(&log_key, None));

    Ok(detected)
}

fn rewritten_history(log: &PublicationLog, publisher: &Keypair) -> Result<PublicationLog> {
    let mut rewritten = PublicationLog::new(*log.operator());
    for record in log.records() {
        let mut metadata = record.metadata.clone();
        let (revision, previous) = rewritten.next_revision(&metadata.purl);
        metadata.revision = revision;
        metadata.previous_revision = previous;
        if rewritten.size() == 0 {
            metadata.artifact_digest = Digest::sha256(b"silently replaced artifact");
        }
        rewritten.append(SignedRecord::sign(metadata, publisher)?)?;
    }
    let extra = examplelib("1.0.1", Vec::new(), at(900))?;
    let identity = log.record(0)?.metadata.publisher.clone();
    rewritten.append(SignedRecord::sign(
        extra.into_metadata(identity, &rewritten)?,
        publisher,
    )?)?;
    Ok(rewritten)
}

pub fn run(dir: &Path) -> Result<ExitCode> {
    prepare(dir)?;
    let ws = Workspace::open(dir)?;
    println!("OpenMeta Witness demonstration");
    println!("data directory: {}", dir.display());

    heading("1. Identities");
    for name in [PUBLISHER, WITNESSES[0], WITNESSES[1]] {
        let key = demo_key(name);
        ws.keys().import(name, &key)?;
        field(name, key.public_key());
    }
    let publisher_key = ws.keys().load(PUBLISHER)?;
    let store = ws.init_log(PUBLISHER)?;
    let log_key = store.operator()?.1;
    info(format!(
        "{PUBLISHER} also operates the publication log {}",
        log_key.fingerprint().short()
    ));
    for witness in WITNESSES {
        ws.create_witness(witness)?;
    }
    info("each witness has its own key and its own database under witnesses/");
    info("private keys are stored under keys/ and never printed");

    heading("2. Publisher A publishes ExampleLib 1.0.0");
    let (index, record) = ws.publish(PUBLISHER, examplelib("1.0.0", Vec::new(), at(60))?)?;
    output::record(index, &record);
    record.verify_publisher(&publisher_key.public_key())?;
    output::verified("Ed25519 signature by publisher-a over the canonical metadata encoding");

    heading("3. Append-only history and checkpoint");
    let cp1 = ws.create_checkpoint(at(120))?;
    output::checkpoint(&cp1);

    heading("4. Independent witness verification");
    for witness in WITNESSES {
        expect_accepted(witness, ws.observe_log(witness, true)?, true)?;
    }
    let (store, log) = ws.load_log()?;
    log.record_proof(index, &cp1)?
        .verify(&log_key, Some(&publisher_key.public_key()))?;
    output::verified(format!(
        "inclusion proof for record #{index} against checkpoint size 1"
    ));

    heading("5. Corrections are new revisions, never overwrites");
    let mut overwrite = record.metadata.clone();
    overwrite.license.spdx_expression = "MIT".into();
    let overwrite = SignedRecord::sign(overwrite, &publisher_key)?;
    let mut scratch = log.clone();
    match store.append(&mut scratch, overwrite) {
        Err(StoreError::Log(e @ LogError::Overwrite { .. })) => output::rejected(e.to_string()),
        other => bail!("overwrite was not rejected: {other:?}"),
    }
    let advisory = VulnerabilityRef {
        id: "GHSA-7m2x-4c9q-examplelib".into(),
        status: VulnerabilityStatus::Affected,
    };
    let (index, correction) =
        ws.publish(PUBLISHER, examplelib("1.0.0", vec![advisory], at(180))?)?;
    output::verified(format!(
        "record #{index}: {} revision {} supersedes {}",
        correction.metadata.purl,
        correction.metadata.revision,
        record.content_hash().short()
    ));
    let cp2 = ws.create_checkpoint(at(240))?;
    output::checkpoint(&cp2);
    for witness in WITNESSES {
        expect_accepted(witness, ws.observe_log(witness, true)?, true)?;
    }
    let mut ledger = ws.ledger()?;
    let receipt = ledger.submit(&AnchorCommitment::from_checkpoint(&cp2), at(300))?;
    output::verified(format!(
        "checkpoint size 2 anchored at ledger height {} as a 104-byte commitment {}",
        receipt.height,
        receipt.commitment.id().short()
    ));
    info("only log id, tree size, root and checkpoint hash are anchored; no metadata or SBOM");

    heading("6. Tampering detection");
    let (_, log) = ws.load_log()?;
    if !tampering_checks(&log, &cp2, 0)? {
        bail!("a tampered record was not detected");
    }
    let rewritten = rewritten_history(&log, &publisher_key)?;
    let rewritten_cp = rewritten.checkpoint(&publisher_key, at(960))?;
    info(format!(
        "operator presents a rewritten history: size {} root {} (record #0 replaced)",
        rewritten_cp.checkpoint.size,
        rewritten_cp.checkpoint.root.short()
    ));
    match expect_rejected(
        WITNESSES[0],
        ws.present(WITNESSES[0], &rewritten, rewritten_cp, true)?,
    )? {
        WitnessError::InconsistentHistory { .. } => {}
        other => bail!("unexpected rejection reason: {other}"),
    }

    heading("7. Conflicting signed checkpoints");
    let (_, release) = ws.publish(PUBLISHER, examplelib("1.1.0", Vec::new(), at(1200))?)?;
    let cp3 = ws.create_checkpoint(at(1260))?;
    info(format!(
        "honest view:      size {} root {} ({} artifact {})",
        cp3.checkpoint.size,
        cp3.checkpoint.root.short(),
        release.metadata.purl,
        release.metadata.artifact_digest.short()
    ));
    let (_, log) = ws.load_log()?;
    let fork = fork_last_record(&log, &publisher_key)?;
    let forked_cp = fork.checkpoint(&publisher_key, at(1260))?;
    let forked_record = fork.record(fork.size() - 1)?;
    info(format!(
        "conflicting view: size {} root {} ({} artifact {})",
        forked_cp.checkpoint.size,
        forked_cp.checkpoint.root.short(),
        forked_record.metadata.purl,
        forked_record.metadata.artifact_digest.short()
    ));
    expect_accepted(
        WITNESSES[0],
        ws.present(WITNESSES[0], &log, cp3.clone(), true)?,
        true,
    )?;
    expect_accepted(
        WITNESSES[1],
        ws.present(WITNESSES[1], &fork, forked_cp.clone(), true)?,
        true,
    )?;
    info("each view is internally valid, so a single witness cannot tell it is being deceived");
    ledger.submit(&AnchorCommitment::from_checkpoint(&cp3), at(1320))?;
    output::verified("honest checkpoint size 3 anchored");
    match ledger.submit(&AnchorCommitment::from_checkpoint(&forked_cp), at(1380)) {
        Err(e @ AnchorError::Conflict { .. }) => {
            output::detected(format!("ledger refused the conflicting commitment: {e}"))
        }
        other => bail!("conflicting anchor was not refused: {other:?}"),
    }

    heading("8. Witnesses compare observations");
    let report = ws.compare_witnesses(WITNESSES[0], WITNESSES[1])?;
    for size in &report.agreed {
        output::verified(format!(
            "witness-a and witness-b agree on checkpoint size {size}"
        ));
    }
    if report.conflicts.len() != 1 {
        bail!(
            "expected exactly one conflict, found {}",
            report.conflicts.len()
        );
    }
    for evidence in &report.conflicts {
        output::evidence(evidence);
        evidence.verify(&log_key)?;
        output::verified(
            "evidence is self-contained: two valid operator signatures over different roots",
        );
    }
    match expect_rejected(
        WITNESSES[0],
        ws.present(WITNESSES[0], &fork, forked_cp, false)?,
    )? {
        WitnessError::Equivocation(_) => {}
        other => bail!("unexpected rejection reason: {other}"),
    }

    heading("9. Persistent state (reloaded from disk)");
    let reopened = LogStore::open(dir.join("log.db"))?;
    let log = reopened.load()?;
    output::verified(format!(
        "publication log: {} records, {} checkpoints, root {}",
        log.size(),
        reopened.checkpoints()?.len(),
        log.root().short()
    ));
    for witness in WITNESSES {
        let store = ws.witness_store(witness)?;
        let restored = store.load(ws.keys().load(witness)?)?;
        output::verified(format!(
            "{witness}: {} cosigned observations, {} equivocation evidence record(s)",
            restored.observations().count(),
            store.evidence()?.len()
        ));
    }
    output::verified(format!(
        "anchor ledger: {} block(s), hash chain intact",
        ws.ledger()?.height()
    ));

    heading("Summary");
    info(
        "signatures, inclusion proofs, consistency proofs and checkpoint comparison all behaved as expected",
    );
    info("witness agreement shows that independent parties saw the same signed history;");
    info("it does not prove that the metadata itself is factually correct");
    println!();
    println!("inspect the persisted state with, for example:");
    println!(
        "  openmeta --data-dir {} witness show witness-b",
        dir.display()
    );
    println!(
        "  openmeta --data-dir {} verify record 0 --publisher {PUBLISHER}",
        dir.display()
    );
    Ok(ExitCode::SUCCESS)
}
