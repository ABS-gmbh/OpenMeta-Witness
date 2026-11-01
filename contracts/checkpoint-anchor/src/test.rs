extern crate std;

use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
use soroban_sdk::{Address, BytesN, Env};

use crate::{AnchorError, CheckpointAnchor, CheckpointAnchorClient};

fn setup() -> (Env, CheckpointAnchorClient<'static>, BytesN<32>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract = env.register(CheckpointAnchor, ());
    let client = CheckpointAnchorClient::new(&env, &contract);
    let log_id = BytesN::from_array(&env, &[7; 32]);
    let operator = Address::generate(&env);
    client.register_log(&log_id, &operator);
    (env, client, log_id, operator)
}

fn digest(env: &Env, byte: u8) -> BytesN<32> {
    BytesN::from_array(env, &[byte; 32])
}

#[test]
fn records_and_returns_commitments() {
    let (env, client, log_id, _) = setup();
    env.ledger().set_sequence_number(42);
    let stored = client.anchor(&log_id, &3, &digest(&env, 1), &digest(&env, 2));
    assert_eq!(env.events().all().events().len(), 1);
    assert_eq!(stored.tree_size, 3);
    assert_eq!(stored.ledger, 42);
    assert_eq!(client.commitment(&log_id, &3), Some(stored.clone()));
    assert_eq!(client.latest(&log_id), Some(stored));
    assert_eq!(client.commitment(&log_id, &4), None);
}

#[test]
fn anchoring_requires_operator_authorization() {
    let (env, client, log_id, operator) = setup();
    client.anchor(&log_id, &1, &digest(&env, 1), &digest(&env, 2));
    let auths = env.auths();
    assert_eq!(auths.len(), 1);
    assert_eq!(auths[0].0, operator);
}

#[test]
fn identical_resubmission_is_idempotent() {
    let (env, client, log_id, _) = setup();
    let first = client.anchor(&log_id, &5, &digest(&env, 1), &digest(&env, 2));
    env.ledger().set_sequence_number(99);
    let second = client.anchor(&log_id, &5, &digest(&env, 1), &digest(&env, 3));
    assert_eq!(first, second);
}

#[test]
fn conflicting_root_for_same_size_is_rejected() {
    let (env, client, log_id, _) = setup();
    client.anchor(&log_id, &5, &digest(&env, 1), &digest(&env, 2));
    let result = client.try_anchor(&log_id, &5, &digest(&env, 9), &digest(&env, 2));
    assert_eq!(result, Err(Ok(AnchorError::ConflictingCommitment)));
    assert_eq!(
        client.commitment(&log_id, &5).unwrap().root,
        digest(&env, 1)
    );
}

#[test]
fn smaller_tree_sizes_are_rejected_after_growth() {
    let (env, client, log_id, _) = setup();
    client.anchor(&log_id, &5, &digest(&env, 1), &digest(&env, 2));
    let result = client.try_anchor(&log_id, &4, &digest(&env, 3), &digest(&env, 4));
    assert_eq!(result, Err(Ok(AnchorError::SizeRegression)));
    client.anchor(&log_id, &6, &digest(&env, 5), &digest(&env, 6));
    assert_eq!(client.latest(&log_id).unwrap().tree_size, 6);
}

#[test]
fn unregistered_logs_and_duplicate_registration_are_rejected() {
    let (env, client, log_id, operator) = setup();
    let unknown = digest(&env, 0xaa);
    assert_eq!(
        client.try_anchor(&unknown, &1, &digest(&env, 1), &digest(&env, 2)),
        Err(Ok(AnchorError::LogNotRegistered))
    );
    assert_eq!(
        client.try_register_log(&log_id, &operator),
        Err(Ok(AnchorError::LogAlreadyRegistered))
    );
}
