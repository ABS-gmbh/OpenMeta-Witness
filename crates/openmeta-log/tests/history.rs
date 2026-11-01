use openmeta_core::{
    Digest, Keypair, License, PackageMetadata, PublisherIdentity, SignedRecord, SourceReference,
    Timestamp, VulnerabilityRef, VulnerabilityStatus,
};
use openmeta_log::{
    CheckpointRelation, LogError, ObserveOutcome, PublicationLog, Witness, WitnessError,
    compare_observations,
};

const T0: u64 = 1_767_225_600;

fn publisher(seed: u8) -> Keypair {
    Keypair::from_seed([seed; 32])
}

fn metadata(key: &Keypair, name: &str, purl: &str, log: &PublicationLog) -> PackageMetadata {
    let purl = purl.parse().unwrap();
    let (revision, previous_revision) = log.next_revision(&purl);
    let version = purl.version().unwrap().to_string();
    PackageMetadata {
        name: name.into(),
        version,
        source: SourceReference {
            repository: format!("https://git.example.org/{name}.git"),
            revision: "9a1c2e7".into(),
        },
        artifact_digest: Digest::sha256(format!("{purl}-artifact").as_bytes()),
        publisher: PublisherIdentity {
            name: format!("publisher-{}", key.public_key().fingerprint().short()),
            public_key: key.public_key(),
        },
        published_at: Timestamp::from_unix_seconds(T0 + log.size()),
        license: License {
            spdx_expression: "Apache-2.0".into(),
        },
        dependencies: Vec::new(),
        vulnerabilities: Vec::new(),
        revision,
        previous_revision,
        purl,
    }
}

fn publish(log: &mut PublicationLog, key: &Keypair, purl: &str) -> u64 {
    let name = purl
        .parse::<openmeta_core::Purl>()
        .unwrap()
        .name()
        .to_string();
    let record = SignedRecord::sign(metadata(key, &name, purl, log), key).unwrap();
    log.append(record).unwrap()
}

#[test]
fn corrections_are_new_revisions_and_overwrites_are_rejected() {
    let operator = publisher(1);
    let key = publisher(2);
    let mut log = PublicationLog::new(operator.public_key());
    publish(&mut log, &key, "pkg:cargo/examplelib@1.0.0");
    let original = log.record(0).unwrap().clone();

    let mut overwrite = metadata(&key, "examplelib", "pkg:cargo/examplelib@1.0.0", &log);
    overwrite.revision = 1;
    overwrite.previous_revision = None;
    overwrite.license.spdx_expression = "MIT".into();
    let overwrite = SignedRecord::sign(overwrite, &key).unwrap();
    assert!(matches!(
        log.append(overwrite),
        Err(LogError::Overwrite {
            revision: 1,
            expected: 2,
            ..
        })
    ));

    let mut skip = metadata(&key, "examplelib", "pkg:cargo/examplelib@1.0.0", &log);
    skip.revision = 3;
    let skip = SignedRecord::sign(skip, &key).unwrap();
    assert!(matches!(
        log.append(skip),
        Err(LogError::UnexpectedRevision {
            expected: 2,
            actual: 3,
            ..
        })
    ));

    let mut unchained = metadata(&key, "examplelib", "pkg:cargo/examplelib@1.0.0", &log);
    unchained.previous_revision = Some(Digest::sha256(b"unrelated"));
    let unchained = SignedRecord::sign(unchained, &key).unwrap();
    assert!(matches!(
        log.append(unchained),
        Err(LogError::BrokenRevisionChain { .. })
    ));

    let mut correction = metadata(&key, "examplelib", "pkg:cargo/examplelib@1.0.0", &log);
    correction.vulnerabilities.push(VulnerabilityRef {
        id: "GHSA-xxxx-yyyy-zzzz".into(),
        status: VulnerabilityStatus::Affected,
    });
    let correction = SignedRecord::sign(correction, &key).unwrap();
    assert_eq!(log.append(correction), Ok(1));

    let history = log.history(&"pkg:cargo/examplelib@1.0.0".parse().unwrap());
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].1, &original);
    assert_eq!(history[1].1.metadata.revision, 2);
    assert_eq!(
        history[1].1.metadata.previous_revision,
        Some(original.content_hash())
    );
}

#[test]
fn package_ownership_and_publisher_names_are_enforced() {
    let operator = publisher(1);
    let owner = publisher(2);
    let intruder = publisher(3);
    let mut log = PublicationLog::new(operator.public_key());
    publish(&mut log, &owner, "pkg:cargo/examplelib@1.0.0");

    let hijack = metadata(&intruder, "examplelib", "pkg:cargo/examplelib@1.1.0", &log);
    let hijack = SignedRecord::sign(hijack, &intruder).unwrap();
    assert!(matches!(
        log.append(hijack),
        Err(LogError::NotPackageOwner { .. })
    ));

    let mut impersonation = metadata(&intruder, "otherlib", "pkg:cargo/otherlib@1.0.0", &log);
    impersonation.publisher.name = log.record(0).unwrap().metadata.publisher.name.clone();
    let impersonation = SignedRecord::sign(impersonation, &intruder).unwrap();
    assert!(matches!(
        log.append(impersonation),
        Err(LogError::PublisherKeyConflict(_))
    ));
    assert_eq!(log.size(), 1);
}

#[test]
fn tampered_records_are_rejected_by_the_log_and_inclusion_proofs() {
    let operator = publisher(1);
    let key = publisher(2);
    let mut log = PublicationLog::new(operator.public_key());
    publish(&mut log, &key, "pkg:cargo/examplelib@1.0.0");
    publish(&mut log, &key, "pkg:cargo/examplelib-core@0.3.0");
    let checkpoint = log
        .checkpoint(&operator, Timestamp::from_unix_seconds(T0 + 10))
        .unwrap();

    let proof = log.record_proof(0, &checkpoint).unwrap();
    assert_eq!(
        proof.verify(&operator.public_key(), Some(&key.public_key())),
        Ok(())
    );

    let mut tampered = proof.clone();
    tampered.record.metadata.source.revision = "deadbeef".into();
    assert!(matches!(
        tampered.verify(&operator.public_key(), None),
        Err(LogError::InvalidRecord(
            openmeta_core::Error::InvalidSignature
        ))
    ));

    let attacker = publisher(9);
    let mut resigned = proof.record.metadata.clone();
    resigned.publisher.public_key = attacker.public_key();
    let mut forged = proof.clone();
    forged.record = SignedRecord::sign(resigned, &attacker).unwrap();
    assert!(matches!(
        forged.verify(&operator.public_key(), None),
        Err(LogError::Proof(_))
    ));
    assert!(matches!(
        forged.verify(&operator.public_key(), Some(&key.public_key())),
        Err(LogError::InvalidRecord(
            openmeta_core::Error::UnexpectedPublisher { .. }
        ))
    ));

    let other = log.record_proof(1, &checkpoint).unwrap();
    let mut swapped = proof;
    swapped.proof = other.proof;
    assert!(matches!(
        swapped.verify(&operator.public_key(), None),
        Err(LogError::Proof(_))
    ));
}

#[test]
fn checkpoints_must_match_the_log_state() {
    let operator = publisher(1);
    let key = publisher(2);
    let mut log = PublicationLog::new(operator.public_key());
    publish(&mut log, &key, "pkg:cargo/examplelib@1.0.0");
    let checkpoint = log
        .checkpoint(&operator, Timestamp::from_unix_seconds(T0))
        .unwrap();
    assert_eq!(log.verify_checkpoint(&checkpoint), Ok(()));

    assert_eq!(
        log.checkpoint(&key, Timestamp::from_unix_seconds(T0)),
        Err(LogError::NotOperator)
    );

    let mut forked = PublicationLog::new(operator.public_key());
    publish(&mut forked, &key, "pkg:cargo/examplelib@1.0.1");
    let forked_checkpoint = forked
        .checkpoint(&operator, Timestamp::from_unix_seconds(T0))
        .unwrap();
    assert_eq!(
        checkpoint.compare(&forked_checkpoint),
        CheckpointRelation::Equivocation
    );
    assert!(matches!(
        log.verify_checkpoint(&forked_checkpoint),
        Err(LogError::CheckpointMismatch { size: 1, .. })
    ));
}

#[test]
fn two_independent_witnesses_verify_the_same_history() {
    let operator = publisher(1);
    let key = publisher(2);
    let mut log = PublicationLog::new(operator.public_key());
    let mut witness_a = Witness::new("witness-a", publisher(20), operator.public_key());
    let mut witness_b = Witness::new("witness-b", publisher(21), operator.public_key());

    for (round, purl) in [
        "pkg:cargo/examplelib@1.0.0",
        "pkg:cargo/examplelib-core@0.3.0",
        "pkg:cargo/examplelib@1.1.0",
    ]
    .into_iter()
    .enumerate()
    {
        publish(&mut log, &key, purl);
        let checkpoint = log
            .checkpoint(&operator, Timestamp::from_unix_seconds(T0 + round as u64))
            .unwrap();
        for witness in [&mut witness_a, &mut witness_b] {
            witness.audit(&checkpoint, log.records()).unwrap();
            let proof = log
                .consistency_proof(witness.latest_size(), checkpoint.checkpoint.size)
                .unwrap();
            let outcome = witness.observe(checkpoint.clone(), &proof).unwrap();
            assert!(matches!(outcome, ObserveOutcome::Accepted(_)));
        }
    }

    assert_eq!(witness_a.latest_size(), 3);
    let a: Vec<_> = witness_a.observations().cloned().collect();
    let b: Vec<_> = witness_b.observations().cloned().collect();
    assert_ne!(a[2].cosignature, b[2].cosignature);
    let report = compare_observations(&operator.public_key(), &a, &b).unwrap();
    assert!(report.is_consistent());
    assert_eq!(report.agreed, vec![1, 2, 3]);

    let again = log.consistency_proof(3, 3).unwrap();
    assert_eq!(
        witness_a.observe(a[2].checkpoint.clone(), &again),
        Ok(ObserveOutcome::AlreadyObserved)
    );
}

#[test]
fn split_view_is_detected_when_witnesses_compare() {
    let operator = publisher(1);
    let key = publisher(2);
    let mut honest = PublicationLog::new(operator.public_key());
    publish(&mut honest, &key, "pkg:cargo/examplelib@1.0.0");
    let mut fork = honest.clone();

    let mut witness_a = Witness::new("witness-a", publisher(20), operator.public_key());
    let mut witness_b = Witness::new("witness-b", publisher(21), operator.public_key());
    let first = honest
        .checkpoint(&operator, Timestamp::from_unix_seconds(T0))
        .unwrap();
    let empty = honest.consistency_proof(0, 1).unwrap();
    witness_a.observe(first.clone(), &empty).unwrap();
    witness_b.observe(first, &empty).unwrap();

    publish(&mut honest, &key, "pkg:cargo/examplelib@1.1.0");
    publish(&mut fork, &key, "pkg:cargo/examplelib@1.1.1");
    let honest_cp = honest
        .checkpoint(&operator, Timestamp::from_unix_seconds(T0 + 1))
        .unwrap();
    let fork_cp = fork
        .checkpoint(&operator, Timestamp::from_unix_seconds(T0 + 1))
        .unwrap();

    witness_a
        .observe(honest_cp.clone(), &honest.consistency_proof(1, 2).unwrap())
        .unwrap();
    witness_b
        .observe(fork_cp.clone(), &fork.consistency_proof(1, 2).unwrap())
        .unwrap();

    let a: Vec<_> = witness_a.observations().cloned().collect();
    let b: Vec<_> = witness_b.observations().cloned().collect();
    let report = compare_observations(&operator.public_key(), &a, &b).unwrap();
    assert!(!report.is_consistent());
    assert_eq!(report.agreed, vec![1]);
    assert_eq!(report.conflicts.len(), 1);
    assert_eq!(report.conflicts[0].verify(&operator.public_key()), Ok(()));

    let proof = fork.consistency_proof(2, 2).unwrap();
    assert!(matches!(
        witness_a.observe(fork_cp, &proof),
        Err(WitnessError::Equivocation(_))
    ));
}

#[test]
fn witnesses_reject_rewritten_history_and_rollbacks() {
    let operator = publisher(1);
    let key = publisher(2);
    let mut honest = PublicationLog::new(operator.public_key());
    publish(&mut honest, &key, "pkg:cargo/examplelib@1.0.0");
    publish(&mut honest, &key, "pkg:cargo/examplelib@1.1.0");
    let mut witness = Witness::new("witness-a", publisher(20), operator.public_key());
    let cp2 = honest
        .checkpoint(&operator, Timestamp::from_unix_seconds(T0))
        .unwrap();
    witness
        .observe(cp2, &honest.consistency_proof(0, 2).unwrap())
        .unwrap();

    let mut rewritten = PublicationLog::new(operator.public_key());
    publish(&mut rewritten, &key, "pkg:cargo/examplelib@1.0.0-evil");
    publish(&mut rewritten, &key, "pkg:cargo/examplelib@1.1.0");
    publish(&mut rewritten, &key, "pkg:cargo/examplelib@1.2.0");
    let cp3 = rewritten
        .checkpoint(&operator, Timestamp::from_unix_seconds(T0 + 1))
        .unwrap();
    let proof = rewritten.consistency_proof(2, 3).unwrap();
    assert!(matches!(
        witness.observe(cp3.clone(), &proof),
        Err(WitnessError::InconsistentHistory { old: 2, new: 3, .. })
    ));
    assert!(matches!(
        witness.observe(cp3, &rewritten.consistency_proof(1, 3).unwrap()),
        Err(WitnessError::ProofSizeMismatch { .. })
    ));

    let mut short = PublicationLog::new(operator.public_key());
    publish(&mut short, &key, "pkg:cargo/examplelib@1.0.0");
    let cp1 = short
        .checkpoint(&operator, Timestamp::from_unix_seconds(T0 + 2))
        .unwrap();
    assert!(matches!(
        witness.observe(cp1, &short.consistency_proof(1, 1).unwrap()),
        Err(WitnessError::Stale {
            offered: 1,
            latest: 2
        })
    ));
    assert_eq!(witness.latest_size(), 2);
}

#[test]
fn witness_audit_detects_tampered_record_contents() {
    let operator = publisher(1);
    let key = publisher(2);
    let mut log = PublicationLog::new(operator.public_key());
    publish(&mut log, &key, "pkg:cargo/examplelib@1.0.0");
    publish(&mut log, &key, "pkg:cargo/examplelib@1.1.0");
    let checkpoint = log
        .checkpoint(&operator, Timestamp::from_unix_seconds(T0))
        .unwrap();
    let witness = Witness::new("witness-a", publisher(20), operator.public_key());
    assert_eq!(witness.audit(&checkpoint, log.records()), Ok(()));

    let mut records = log.records().to_vec();
    records[1].metadata.license.spdx_expression = "GPL-3.0-only".into();
    assert!(matches!(
        witness.audit(&checkpoint, &records),
        Err(WitnessError::AuditRejected(LogError::InvalidRecord(_)))
    ));

    let mut substituted = log.records().to_vec();
    let mut other = PublicationLog::new(operator.public_key());
    publish(&mut other, &key, "pkg:cargo/examplelib@1.0.0");
    publish(&mut other, &key, "pkg:cargo/examplelib@1.1.5");
    substituted[1] = other.record(1).unwrap().clone();
    assert!(matches!(
        witness.audit(&checkpoint, &substituted),
        Err(WitnessError::AuditRejected(
            LogError::CheckpointMismatch { .. }
        ))
    ));

    assert!(matches!(
        witness.audit(&checkpoint, &log.records()[..1]),
        Err(WitnessError::AuditIncomplete { .. })
    ));
}

#[test]
fn restored_witness_rejects_tampered_observations() {
    let operator = publisher(1);
    let key = publisher(2);
    let mut log = PublicationLog::new(operator.public_key());
    publish(&mut log, &key, "pkg:cargo/examplelib@1.0.0");
    let mut witness = Witness::new("witness-a", publisher(20), operator.public_key());
    let checkpoint = log
        .checkpoint(&operator, Timestamp::from_unix_seconds(T0))
        .unwrap();
    witness
        .observe(checkpoint, &log.consistency_proof(0, 1).unwrap())
        .unwrap();
    let observations: Vec<_> = witness.observations().cloned().collect();

    let restored = Witness::restore(
        "witness-a",
        publisher(20),
        operator.public_key(),
        observations.clone(),
    )
    .unwrap();
    assert_eq!(restored.latest(), witness.latest());

    let mut tampered = observations;
    tampered[0].checkpoint.checkpoint.root = Digest::sha256(b"x");
    assert!(matches!(
        Witness::restore("witness-a", publisher(20), operator.public_key(), tampered),
        Err(WitnessError::InvalidObservation { .. })
    ));
}
