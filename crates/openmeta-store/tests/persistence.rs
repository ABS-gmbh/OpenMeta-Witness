use openmeta_core::{
    Digest, Keypair, License, PackageMetadata, PublisherIdentity, SignedRecord, SourceReference,
    Timestamp,
};
use openmeta_log::{PublicationLog, Witness};
use openmeta_store::{Keystore, LogStore, StoreError, WitnessStore};
use rusqlite::Connection;

fn record(key: &Keypair, log: &PublicationLog, version: &str) -> SignedRecord {
    let purl = format!("pkg:cargo/examplelib@{version}").parse().unwrap();
    let (revision, previous_revision) = log.next_revision(&purl);
    let metadata = PackageMetadata {
        purl,
        name: "examplelib".into(),
        version: version.into(),
        source: SourceReference {
            repository: "https://git.example.org/examplelib.git".into(),
            revision: "c0ffee1".into(),
        },
        artifact_digest: Digest::sha256(version.as_bytes()),
        publisher: PublisherIdentity {
            name: "publisher-a".into(),
            public_key: key.public_key(),
        },
        published_at: Timestamp::from_unix_seconds(1_767_225_600),
        license: License {
            spdx_expression: "MIT".into(),
        },
        dependencies: Vec::new(),
        vulnerabilities: Vec::new(),
        revision,
        previous_revision,
    };
    SignedRecord::sign(metadata, key).unwrap()
}

fn publish(store: &LogStore, log: &mut PublicationLog, key: &Keypair, version: &str) {
    let next = record(key, log, version);
    store.append(log, next).unwrap();
}

#[test]
fn log_and_checkpoints_survive_reopening() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("log.db");
    let operator = Keypair::from_seed([1; 32]);
    let publisher = Keypair::from_seed([2; 32]);

    let root = {
        let store = LogStore::create(&path, "operator", &operator.public_key()).unwrap();
        let mut log = store.load().unwrap();
        publish(&store, &mut log, &publisher, "1.0.0");
        publish(&store, &mut log, &publisher, "1.1.0");
        let checkpoint = log
            .checkpoint(&operator, Timestamp::from_unix_seconds(1_767_225_700))
            .unwrap();
        store.save_checkpoint(&log, &checkpoint).unwrap();
        log.root()
    };

    let store = LogStore::open(&path).unwrap();
    let log = store.load().unwrap();
    assert_eq!(log.size(), 2);
    assert_eq!(log.root(), root);
    let checkpoint = store.latest_checkpoint().unwrap().unwrap();
    assert_eq!(checkpoint.checkpoint.root, root);
    assert!(matches!(
        LogStore::create(&path, "operator", &operator.public_key()),
        Err(StoreError::AlreadyInitialized(_))
    ));
}

#[test]
fn database_rejects_in_place_modification() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("log.db");
    let operator = Keypair::from_seed([1; 32]);
    let publisher = Keypair::from_seed([2; 32]);
    let store = LogStore::create(&path, "operator", &operator.public_key()).unwrap();
    let mut log = store.load().unwrap();
    publish(&store, &mut log, &publisher, "1.0.0");

    let conn = Connection::open(&path).unwrap();
    let err = conn
        .execute("UPDATE entries SET record = '{}' WHERE idx = 0", [])
        .unwrap_err();
    assert!(err.to_string().contains("append-only"));
    let err = conn.execute("DELETE FROM entries", []).unwrap_err();
    assert!(err.to_string().contains("append-only"));
}

#[test]
fn tampering_that_bypasses_triggers_is_detected_on_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("log.db");
    let operator = Keypair::from_seed([1; 32]);
    let publisher = Keypair::from_seed([2; 32]);
    {
        let store = LogStore::create(&path, "operator", &operator.public_key()).unwrap();
        let mut log = store.load().unwrap();
        publish(&store, &mut log, &publisher, "1.0.0");
    }

    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(
        "DROP TRIGGER entries_no_update;
         UPDATE entries SET record = replace(record, '\"MIT\"', '\"GPL-3.0-only\"');",
    )
    .unwrap();
    drop(conn);

    let store = LogStore::open(&path).unwrap();
    assert!(matches!(store.load(), Err(StoreError::Corrupted(_))));
}

#[test]
fn conflicting_checkpoint_cannot_be_stored() {
    let dir = tempfile::tempdir().unwrap();
    let operator = Keypair::from_seed([1; 32]);
    let publisher = Keypair::from_seed([2; 32]);
    let store = LogStore::create(
        dir.path().join("log.db"),
        "operator",
        &operator.public_key(),
    )
    .unwrap();
    let mut log = store.load().unwrap();
    publish(&store, &mut log, &publisher, "1.0.0");
    let first = log
        .checkpoint(&operator, Timestamp::from_unix_seconds(1_767_225_700))
        .unwrap();
    store.save_checkpoint(&log, &first).unwrap();
    let resigned = log
        .checkpoint(&operator, Timestamp::from_unix_seconds(1_767_225_800))
        .unwrap();
    store.save_checkpoint(&log, &resigned).unwrap();
    assert_eq!(store.checkpoints().unwrap(), vec![first]);

    let mut fork = PublicationLog::new(operator.public_key());
    let next = record(&publisher, &fork, "9.9.9");
    fork.append(next).unwrap();
    let forged = fork
        .checkpoint(&operator, Timestamp::from_unix_seconds(1_767_225_700))
        .unwrap();
    assert!(store.save_checkpoint(&log, &forged).is_err());
}

#[test]
fn witness_state_survives_reopening() {
    let dir = tempfile::tempdir().unwrap();
    let operator = Keypair::from_seed([1; 32]);
    let publisher = Keypair::from_seed([2; 32]);
    let keys = Keystore::open(dir.path().join("keys")).unwrap();
    keys.create("witness-a").unwrap();
    let path = dir.path().join("witness-a.db");

    let mut log = PublicationLog::new(operator.public_key());
    let next = record(&publisher, &log, "1.0.0");
    log.append(next).unwrap();
    let checkpoint = log
        .checkpoint(&operator, Timestamp::from_unix_seconds(1_767_225_700))
        .unwrap();

    {
        let store = WitnessStore::create(&path, "witness-a", &operator.public_key()).unwrap();
        let mut witness = store.load(keys.load("witness-a").unwrap()).unwrap();
        let outcome = witness
            .observe(checkpoint.clone(), &log.consistency_proof(0, 1).unwrap())
            .unwrap();
        let openmeta_log::ObserveOutcome::Accepted(observation) = outcome else {
            panic!("expected a new observation");
        };
        store.add_observation(&observation).unwrap();
    }

    let store = WitnessStore::open(&path).unwrap();
    let witness: Witness = store.load(keys.load("witness-a").unwrap()).unwrap();
    assert_eq!(witness.latest_size(), 1);
    assert_eq!(witness.latest().unwrap().checkpoint, checkpoint);

    let wrong_key = Keypair::from_seed([77; 32]);
    assert!(matches!(store.load(wrong_key), Err(StoreError::Witness(_))));
}
