#![no_std]

use soroban_sdk::{
    Address, BytesN, Env, contract, contracterror, contractevent, contractimpl, contracttype,
};

#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u32)]
pub enum AnchorError {
    LogAlreadyRegistered = 1,
    LogNotRegistered = 2,
    ConflictingCommitment = 3,
    SizeRegression = 4,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitment {
    pub tree_size: u64,
    pub root: BytesN<32>,
    pub checkpoint_hash: BytesN<32>,
    pub ledger: u32,
}

#[contracttype]
enum DataKey {
    Operator(BytesN<32>),
    Latest(BytesN<32>),
    Commitment(BytesN<32>, u64),
}

#[contractevent]
pub struct CheckpointAnchored {
    #[topic]
    pub log_id: BytesN<32>,
    pub tree_size: u64,
    pub root: BytesN<32>,
}

#[contract]
pub struct CheckpointAnchor;

#[contractimpl]
impl CheckpointAnchor {
    pub fn register_log(
        env: Env,
        log_id: BytesN<32>,
        operator: Address,
    ) -> Result<(), AnchorError> {
        operator.require_auth();
        let key = DataKey::Operator(log_id);
        if env.storage().persistent().has(&key) {
            return Err(AnchorError::LogAlreadyRegistered);
        }
        env.storage().persistent().set(&key, &operator);
        Ok(())
    }

    pub fn anchor(
        env: Env,
        log_id: BytesN<32>,
        tree_size: u64,
        root: BytesN<32>,
        checkpoint_hash: BytesN<32>,
    ) -> Result<Commitment, AnchorError> {
        let operator: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Operator(log_id.clone()))
            .ok_or(AnchorError::LogNotRegistered)?;
        operator.require_auth();

        let key = DataKey::Commitment(log_id.clone(), tree_size);
        if let Some(existing) = env.storage().persistent().get::<_, Commitment>(&key) {
            return if existing.root == root {
                Ok(existing)
            } else {
                Err(AnchorError::ConflictingCommitment)
            };
        }
        let latest_key = DataKey::Latest(log_id.clone());
        if let Some(latest) = env.storage().persistent().get::<_, u64>(&latest_key)
            && tree_size < latest
        {
            return Err(AnchorError::SizeRegression);
        }

        let commitment = Commitment {
            tree_size,
            root: root.clone(),
            checkpoint_hash,
            ledger: env.ledger().sequence(),
        };
        env.storage().persistent().set(&key, &commitment);
        env.storage().persistent().set(&latest_key, &tree_size);
        CheckpointAnchored {
            log_id,
            tree_size,
            root,
        }
        .publish(&env);
        Ok(commitment)
    }

    pub fn commitment(env: Env, log_id: BytesN<32>, tree_size: u64) -> Option<Commitment> {
        env.storage()
            .persistent()
            .get(&DataKey::Commitment(log_id, tree_size))
    }

    pub fn latest(env: Env, log_id: BytesN<32>) -> Option<Commitment> {
        let size: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::Latest(log_id.clone()))?;
        Self::commitment(env, log_id, size)
    }
}

#[cfg(test)]
mod test;
