use std::fs;
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, Result, anyhow, bail};
use openmeta_anchor::{AnchorBackend, AnchorCommitment, AnchorStatus, check_anchor};
use openmeta_core::{
    DependencyRef, Digest, PublicKey, Purl, SignedRecord, Timestamp, VulnerabilityRef,
    VulnerabilityStatus,
};
use openmeta_log::{
    CheckpointRelation, EquivocationEvidence, PublicationLog, RecordProof, SignedCheckpoint,
};
use openmeta_store::StoreError;

use crate::output;
use crate::workspace::{Draft, Verdict, Workspace};
use crate::{
    AnchorCommand, CheckpointCommand, Command, IdentityCommand, LogCommand, PublishArgs,
    SimulateCommand, VerifyCommand, WitnessCommand, demo,
};

const DETECTED_EXIT: u8 = 2;

pub fn run(data_dir: &Path, command: Command) -> Result<ExitCode> {
    let ws = Workspace::open(data_dir)?;
    match command {
        Command::Identity(command) => identity(&ws, command),
        Command::Log(command) => log(&ws, command),
        Command::Publish(args) => publish(&ws, args),
        Command::Inspect { index, purl } => inspect(&ws, index, purl),
        Command::Checkpoint(command) => checkpoint(&ws, command),
        Command::Prove { index, size, out } => {
            let (store, log) = ws.load_log()?;
            let checkpoint = match size {
                Some(size) => store
                    .checkpoint(size)?
                    .ok_or_else(|| anyhow!("no checkpoint for size {size}"))?,
                None => ws.latest_checkpoint()?,
            };
            let bundle = serde_json::to_string_pretty(&log.record_proof(index, &checkpoint)?)?;
            match out {
                Some(path) => {
                    fs::write(&path, bundle)?;
                    println!(
                        "proof bundle for record #{index} written to {}",
                        path.display()
                    );
                }
                None => println!("{bundle}"),
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Verify(command) => verify(&ws, command),
        Command::Witness(command) => witness(&ws, command),
        Command::Anchor(command) => anchor(&ws, command),
        Command::Simulate(command) => simulate(&ws, command),
        Command::Demo { dir } => demo::run(&dir),
    }
}

fn now_or(timestamp: Option<u64>) -> Timestamp {
    timestamp.map_or_else(Timestamp::now, Timestamp::from_unix_seconds)
}

fn identity(ws: &Workspace, command: IdentityCommand) -> Result<ExitCode> {
    match command {
        IdentityCommand::New { name } => {
            let key = ws.keys().create(&name)?;
            println!("created identity `{name}`");
            output::field("public key", key);
            output::field("fingerprint", key.fingerprint());
            output::field(
                "secret key",
                format!(
                    "stored in {}/keys/{name}.secret (not displayed)",
                    ws.root().display()
                ),
            );
        }
        IdentityCommand::List => {
            for (name, key) in ws.keys().list()? {
                println!("{name:<20} {key}");
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn log(ws: &Workspace, command: LogCommand) -> Result<ExitCode> {
    match command {
        LogCommand::Init { operator } => {
            let store = ws.init_log(&operator)?;
            let (_, key) = store.operator()?;
            println!("initialised publication log operated by `{operator}`");
            output::field("log id", key.fingerprint());
        }
        LogCommand::Verify => {
            let (store, log) = ws.load_log()?;
            let checkpoints = store.checkpoints()?;
            for pair in checkpoints.windows(2) {
                let (old, new) = (&pair[0].checkpoint, &pair[1].checkpoint);
                log.consistency_proof(old.size, new.size)?
                    .verify(&old.root, &new.root)?;
            }
            output::verified(format!(
                "{} records replayed: signatures, publisher bindings and revision chains are valid",
                log.size()
            ));
            output::verified(format!(
                "{} stored checkpoints match the log and are mutually consistent",
                checkpoints.len()
            ));
            output::field("current root", log.root());
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn parse_dependency(value: &str) -> Result<DependencyRef> {
    let (purl, requirement) = match value.split_once('=') {
        Some((purl, requirement)) => (purl, Some(requirement.to_string())),
        None => (value, None),
    };
    Ok(DependencyRef {
        purl: purl.parse()?,
        requirement,
    })
}

fn parse_vulnerability(value: &str) -> Result<VulnerabilityRef> {
    let (id, status) = value
        .split_once('=')
        .ok_or_else(|| anyhow!("vulnerability must be written as ID=STATUS"))?;
    let status = match status {
        "affected" => VulnerabilityStatus::Affected,
        "not_affected" => VulnerabilityStatus::NotAffected,
        "fixed" => VulnerabilityStatus::Fixed,
        "under_investigation" => VulnerabilityStatus::UnderInvestigation,
        other => bail!(
            "unknown vulnerability status `{other}` (use affected, not_affected, fixed or under_investigation)"
        ),
    };
    Ok(VulnerabilityRef {
        id: id.to_string(),
        status,
    })
}

fn publish(ws: &Workspace, args: PublishArgs) -> Result<ExitCode> {
    let artifact_digest = match (&args.digest, &args.artifact) {
        (Some(hex), _) => hex.parse()?,
        (None, Some(path)) => Digest::sha256(
            &fs::read(path).with_context(|| format!("reading artifact {}", path.display()))?,
        ),
        (None, None) => bail!("either --digest or --artifact is required"),
    };
    let draft = Draft {
        purl: args.purl.parse()?,
        repository: args.repository,
        source_revision: args.source_revision,
        artifact_digest,
        license: args.license,
        dependencies: args
            .dependencies
            .iter()
            .map(|d| parse_dependency(d))
            .collect::<Result<_>>()?,
        vulnerabilities: args
            .vulnerabilities
            .iter()
            .map(|v| parse_vulnerability(v))
            .collect::<Result<_>>()?,
        published_at: now_or(args.timestamp),
    };
    let (index, record) = ws.publish(&args.publisher, draft)?;
    output::verified(format!(
        "metadata signed by `{}` and appended to the log",
        args.publisher
    ));
    output::record(index, &record);
    Ok(ExitCode::SUCCESS)
}

fn inspect(ws: &Workspace, index: Option<u64>, purl: Option<String>) -> Result<ExitCode> {
    let (_, log) = ws.load_log()?;
    let selected: Vec<(u64, &SignedRecord)> = match (index, purl) {
        (Some(index), _) => vec![(index, log.record(index)?)],
        (None, Some(purl)) => log.history(&purl.parse::<Purl>()?),
        (None, None) => log
            .records()
            .iter()
            .enumerate()
            .map(|(i, r)| (i as u64, r))
            .collect(),
    };
    if selected.is_empty() {
        println!("no matching records");
    }
    for (index, record) in selected {
        output::record(index, record);
    }
    Ok(ExitCode::SUCCESS)
}

fn read_checkpoint(path: &Path) -> Result<SignedCheckpoint> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(serde_json::from_str(&text)?)
}

fn checkpoint(ws: &Workspace, command: CheckpointCommand) -> Result<ExitCode> {
    match command {
        CheckpointCommand::Create { timestamp } => {
            let checkpoint = ws.create_checkpoint(now_or(timestamp))?;
            output::verified("checkpoint signed by the log operator");
            output::checkpoint(&checkpoint);
        }
        CheckpointCommand::Show { size, json } => {
            let checkpoint = match size {
                Some(size) => ws
                    .log_store()?
                    .checkpoint(size)?
                    .ok_or_else(|| anyhow!("no checkpoint for size {size}"))?,
                None => ws.latest_checkpoint()?,
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&checkpoint)?);
            } else {
                output::checkpoint(&checkpoint);
            }
        }
        CheckpointCommand::List => {
            for checkpoint in ws.log_store()?.checkpoints()? {
                let cp = &checkpoint.checkpoint;
                println!(
                    "size {:>4}  root {}  {}",
                    cp.size,
                    cp.root,
                    output::format_time(cp.timestamp)
                );
            }
        }
        CheckpointCommand::Compare { first, second } => {
            let (_, log_key) = ws.log_store()?.operator()?;
            let (a, b) = (read_checkpoint(&first)?, read_checkpoint(&second)?);
            for (path, checkpoint) in [(&first, &a), (&second, &b)] {
                match checkpoint.verify(&log_key) {
                    Ok(()) => output::verified(format!(
                        "{} is signed by the log operator",
                        path.display()
                    )),
                    Err(e) => {
                        output::detected(format!("{}: {e}", path.display()));
                        return Ok(ExitCode::from(DETECTED_EXIT));
                    }
                }
            }
            match a.compare(&b) {
                CheckpointRelation::Identical | CheckpointRelation::SameStateResigned => {
                    output::verified("both checkpoints commit to the same log state")
                }
                CheckpointRelation::DifferentSizes => {
                    let (_, log) = ws.load_log()?;
                    let (old, new) = if a.checkpoint.size < b.checkpoint.size {
                        (&a, &b)
                    } else {
                        (&b, &a)
                    };
                    let proof = log.consistency_proof(old.checkpoint.size, new.checkpoint.size)?;
                    match proof.verify(&old.checkpoint.root, &new.checkpoint.root) {
                        Ok(()) => output::verified(format!(
                            "size {} is a prefix of size {} (consistency proof verified)",
                            old.checkpoint.size, new.checkpoint.size
                        )),
                        Err(e) => {
                            output::detected(format!(
                                "the checkpoints describe diverging histories: {e}"
                            ));
                            return Ok(ExitCode::from(DETECTED_EXIT));
                        }
                    }
                }
                CheckpointRelation::Equivocation => {
                    output::evidence(&EquivocationEvidence::new(a, b, &log_key)?);
                    return Ok(ExitCode::from(DETECTED_EXIT));
                }
                CheckpointRelation::DifferentLogs => bail!("checkpoints belong to different logs"),
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn verify(ws: &Workspace, command: VerifyCommand) -> Result<ExitCode> {
    let (log_key, bundle, expected) = match command {
        VerifyCommand::Record { index, publisher } => {
            let (store, log) = ws.load_log()?;
            let checkpoint = ws.latest_checkpoint()?;
            let expected = publisher.map(|p| ws.keys().public_key(&p)).transpose()?;
            (
                store.operator()?.1,
                log.record_proof(index, &checkpoint)?,
                expected,
            )
        }
        VerifyCommand::Proof {
            file,
            publisher_key,
        } => {
            let text =
                fs::read_to_string(&file).with_context(|| format!("reading {}", file.display()))?;
            let bundle: RecordProof = serde_json::from_str(&text)?;
            let expected = publisher_key.map(|k| k.parse::<PublicKey>()).transpose()?;
            (ws.log_store()?.operator()?.1, bundle, expected)
        }
    };
    match bundle.verify(&log_key, expected.as_ref()) {
        Ok(()) => {
            let m = &bundle.record.metadata;
            output::verified(format!(
                "{} revision {} signed by `{}`",
                m.purl, m.revision, m.publisher.name
            ));
            output::verified(format!(
                "included at index {} of checkpoint size {} (root {})",
                bundle.proof.leaf_index,
                bundle.checkpoint.checkpoint.size,
                bundle.checkpoint.checkpoint.root.short()
            ));
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            output::detected(format!("verification failed: {e}"));
            Ok(ExitCode::from(DETECTED_EXIT))
        }
    }
}

fn report_observed(witness: &str, observed: &Verdict) -> ExitCode {
    match observed {
        Verdict::Accepted(observation) => {
            output::verified(format!(
                "{witness} accepted checkpoint size {} (root {}) and cosigned it",
                observation.size(),
                observation.checkpoint.checkpoint.root.short()
            ));
            ExitCode::SUCCESS
        }
        Verdict::AlreadyObserved => {
            output::verified(format!("{witness} had already observed this checkpoint"));
            ExitCode::SUCCESS
        }
        Verdict::Rejected(openmeta_log::WitnessError::Equivocation(evidence)) => {
            output::evidence(evidence);
            ExitCode::from(DETECTED_EXIT)
        }
        Verdict::Rejected(e) => {
            output::detected(format!("{witness} rejected the checkpoint: {e}"));
            ExitCode::from(DETECTED_EXIT)
        }
    }
}

fn witness(ws: &Workspace, command: WitnessCommand) -> Result<ExitCode> {
    match command {
        WitnessCommand::New { name } => {
            let key = match ws.keys().public_key(&name) {
                Ok(key) => key,
                Err(StoreError::KeyNotFound(_)) => ws.keys().create(&name)?,
                Err(e) => return Err(e.into()),
            };
            ws.create_witness(&name)?;
            println!("created witness `{name}`");
            output::field("witness key", key);
        }
        WitnessCommand::Observe { name, no_audit } => {
            let observed = ws.observe_log(&name, !no_audit)?;
            return Ok(report_observed(&name, &observed));
        }
        WitnessCommand::Show { name } => {
            let store = ws.witness_store(&name)?;
            let (_, log_key) = store.config()?;
            println!("witness `{name}` following log {}", log_key.fingerprint());
            for observation in store.observations()? {
                let cp = &observation.checkpoint.checkpoint;
                println!(
                    "  observed size {:>4}  root {}  cosignature {}",
                    cp.size, cp.root, observation.cosignature.signature
                );
            }
            for evidence in store.evidence()? {
                output::evidence(&evidence);
            }
        }
        WitnessCommand::Compare { first, second } => {
            let report = ws.compare_witnesses(&first, &second)?;
            for size in &report.agreed {
                output::verified(format!("{first} and {second} agree on size {size}"));
            }
            for size in &report.only_first {
                output::info(format!("only {first} observed size {size}"));
            }
            for size in &report.only_second {
                output::info(format!("only {second} observed size {size}"));
            }
            for evidence in &report.conflicts {
                output::evidence(evidence);
            }
            if !report.is_consistent() {
                return Ok(ExitCode::from(DETECTED_EXIT));
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn select_checkpoint(ws: &Workspace, size: Option<u64>) -> Result<SignedCheckpoint> {
    match size {
        Some(size) => ws
            .log_store()?
            .checkpoint(size)?
            .ok_or_else(|| anyhow!("no checkpoint for size {size}")),
        None => ws.latest_checkpoint(),
    }
}

fn anchor(ws: &Workspace, command: AnchorCommand) -> Result<ExitCode> {
    match command {
        AnchorCommand::Submit { size } => {
            let checkpoint = select_checkpoint(ws, size)?;
            let (_, log_key) = ws.log_store()?.operator()?;
            checkpoint.verify(&log_key)?;
            let receipt = ws.ledger()?.submit(
                &AnchorCommitment::from_checkpoint(&checkpoint),
                Timestamp::now(),
            )?;
            output::verified(format!(
                "checkpoint size {} anchored at height {}",
                checkpoint.checkpoint.size, receipt.height
            ));
            output::field("commitment", receipt.commitment.id());
            output::field("block hash", receipt.block_hash);
        }
        AnchorCommand::Verify { size } => {
            let checkpoint = select_checkpoint(ws, size)?;
            match check_anchor(&ws.ledger()?, &checkpoint)? {
                AnchorStatus::Anchored(receipt) => output::verified(format!(
                    "checkpoint size {} matches the commitment anchored at height {}",
                    checkpoint.checkpoint.size, receipt.height
                )),
                AnchorStatus::NotAnchored => output::info(format!(
                    "checkpoint size {} is not anchored",
                    checkpoint.checkpoint.size
                )),
                AnchorStatus::Conflict(receipt) => {
                    output::detected(format!(
                        "anchored root {} differs from checkpoint root {}",
                        receipt.commitment.root, checkpoint.checkpoint.root
                    ));
                    return Ok(ExitCode::from(DETECTED_EXIT));
                }
            }
        }
        AnchorCommand::List => {
            for receipt in ws.ledger()?.receipts() {
                let c = &receipt.commitment;
                println!(
                    "height {:>3}  log {}  size {:>4}  root {}",
                    receipt.height,
                    c.log_id.short(),
                    c.tree_size,
                    c.root
                );
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn simulate(ws: &Workspace, command: SimulateCommand) -> Result<ExitCode> {
    match command {
        SimulateCommand::Tamper { index } => {
            let (_, log) = ws.load_log()?;
            let checkpoint = ws.latest_checkpoint()?;
            let all_detected = demo::tampering_checks(&log, &checkpoint, index)?;
            Ok(if all_detected {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
        SimulateCommand::Equivocate { witness, publisher } => {
            let (store, log) = ws.load_log()?;
            let (operator, _) = store.operator()?;
            let fork = fork_last_record(&log, &ws.keys().load(&publisher)?)?;
            let forked = fork.checkpoint(&ws.keys().load(&operator)?, Timestamp::now())?;
            output::info(format!(
                "log operator signed a conflicting checkpoint: size {} root {}",
                forked.checkpoint.size,
                forked.checkpoint.root.short()
            ));
            let observed = ws.present(&witness, &fork, forked, true)?;
            Ok(report_observed(&witness, &observed))
        }
    }
}

pub fn fork_last_record(
    log: &PublicationLog,
    publisher: &openmeta_core::Keypair,
) -> Result<PublicationLog> {
    let (last, prefix) = log
        .records()
        .split_last()
        .ok_or_else(|| anyhow!("the log is empty; there is nothing to fork"))?;
    if last.metadata.publisher.public_key != publisher.public_key() {
        bail!("the latest record was not published by this identity");
    }
    let mut metadata = last.metadata.clone();
    metadata.artifact_digest = Digest::tagged(
        "openmeta/forked-artifact",
        metadata.artifact_digest.as_bytes(),
    );
    let mut fork = PublicationLog::from_records(*log.operator(), prefix.iter().cloned())?;
    fork.append(SignedRecord::sign(metadata, publisher)?)?;
    Ok(fork)
}
