use openmeta_core::Digest;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProofError {
    #[error("leaf index {index} is outside a tree of size {size}")]
    IndexOutOfRange { index: u64, size: u64 },
    #[error("tree size {requested} exceeds the current size {available}")]
    SizeOutOfRange { requested: u64, available: u64 },
    #[error("consistency proof requires old size {old} <= new size {new}")]
    InvalidSizes { old: u64, new: u64 },
    #[error("proof does not match the expected root")]
    RootMismatch,
    #[error("proof has an invalid length")]
    MalformedProof,
}

pub fn leaf_hash(data: &[u8]) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(data);
    Digest::from_bytes(hasher.finalize().into())
}

fn node_hash(left: &Digest, right: &Digest) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    Digest::from_bytes(hasher.finalize().into())
}

fn split_point(n: usize) -> usize {
    debug_assert!(n > 1);
    1 << (usize::BITS - 1 - (n - 1).leading_zeros())
}

fn subtree_root(leaves: &[Digest]) -> Digest {
    match leaves.len() {
        0 => Digest::sha256(&[]),
        1 => leaves[0],
        n => {
            let k = split_point(n);
            node_hash(&subtree_root(&leaves[..k]), &subtree_root(&leaves[k..]))
        }
    }
}

fn inclusion_path(index: usize, leaves: &[Digest], path: &mut Vec<Digest>) {
    let n = leaves.len();
    if n <= 1 {
        return;
    }
    let k = split_point(n);
    if index < k {
        inclusion_path(index, &leaves[..k], path);
        path.push(subtree_root(&leaves[k..]));
    } else {
        inclusion_path(index - k, &leaves[k..], path);
        path.push(subtree_root(&leaves[..k]));
    }
}

fn consistency_path(old: usize, leaves: &[Digest], complete: bool, path: &mut Vec<Digest>) {
    let n = leaves.len();
    if old == n {
        if !complete {
            path.push(subtree_root(leaves));
        }
        return;
    }
    let k = split_point(n);
    if old <= k {
        consistency_path(old, &leaves[..k], complete, path);
        path.push(subtree_root(&leaves[k..]));
    } else {
        consistency_path(old - k, &leaves[k..], false, path);
        path.push(subtree_root(&leaves[..k]));
    }
}

#[derive(Clone, Debug, Default)]
pub struct MerkleTree {
    leaves: Vec<Digest>,
}

impl MerkleTree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, leaf: Digest) -> u64 {
        self.leaves.push(leaf);
        self.size() - 1
    }

    pub fn size(&self) -> u64 {
        self.leaves.len() as u64
    }

    pub fn leaf(&self, index: u64) -> Option<Digest> {
        self.leaves.get(index as usize).copied()
    }

    pub fn root(&self) -> Digest {
        subtree_root(&self.leaves)
    }

    pub fn root_at(&self, size: u64) -> Result<Digest, ProofError> {
        Ok(subtree_root(self.prefix(size)?))
    }

    fn prefix(&self, size: u64) -> Result<&[Digest], ProofError> {
        if size > self.size() {
            return Err(ProofError::SizeOutOfRange {
                requested: size,
                available: self.size(),
            });
        }
        Ok(&self.leaves[..size as usize])
    }

    pub fn inclusion_proof(&self, index: u64, size: u64) -> Result<InclusionProof, ProofError> {
        let leaves = self.prefix(size)?;
        if index >= size {
            return Err(ProofError::IndexOutOfRange { index, size });
        }
        let mut path = Vec::new();
        inclusion_path(index as usize, leaves, &mut path);
        Ok(InclusionProof {
            leaf_index: index,
            tree_size: size,
            path,
        })
    }

    pub fn consistency_proof(&self, old: u64, new: u64) -> Result<ConsistencyProof, ProofError> {
        if old > new {
            return Err(ProofError::InvalidSizes { old, new });
        }
        let leaves = self.prefix(new)?;
        let mut path = Vec::new();
        if old > 0 {
            consistency_path(old as usize, leaves, true, &mut path);
        }
        Ok(ConsistencyProof {
            old_size: old,
            new_size: new,
            path,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    pub leaf_index: u64,
    pub tree_size: u64,
    pub path: Vec<Digest>,
}

impl InclusionProof {
    pub fn verify(&self, leaf: &Digest, root: &Digest) -> Result<(), ProofError> {
        if self.leaf_index >= self.tree_size {
            return Err(ProofError::IndexOutOfRange {
                index: self.leaf_index,
                size: self.tree_size,
            });
        }
        let mut f_n = self.leaf_index;
        let mut s_n = self.tree_size - 1;
        let mut hash = *leaf;
        for sibling in &self.path {
            if s_n == 0 {
                return Err(ProofError::MalformedProof);
            }
            if f_n & 1 == 1 || f_n == s_n {
                hash = node_hash(sibling, &hash);
                while f_n & 1 == 0 && f_n != 0 {
                    f_n >>= 1;
                    s_n >>= 1;
                }
            } else {
                hash = node_hash(&hash, sibling);
            }
            f_n >>= 1;
            s_n >>= 1;
        }
        if s_n != 0 {
            return Err(ProofError::MalformedProof);
        }
        if hash != *root {
            return Err(ProofError::RootMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsistencyProof {
    pub old_size: u64,
    pub new_size: u64,
    pub path: Vec<Digest>,
}

impl ConsistencyProof {
    pub fn verify(&self, old_root: &Digest, new_root: &Digest) -> Result<(), ProofError> {
        let (old, new) = (self.old_size, self.new_size);
        if old > new {
            return Err(ProofError::InvalidSizes { old, new });
        }
        if old == 0 {
            return if self.path.is_empty() {
                Ok(())
            } else {
                Err(ProofError::MalformedProof)
            };
        }
        if old == new {
            if !self.path.is_empty() {
                return Err(ProofError::MalformedProof);
            }
            return if old_root == new_root {
                Ok(())
            } else {
                Err(ProofError::RootMismatch)
            };
        }

        let mut path = self.path.as_slice();
        let seed = if old.is_power_of_two() {
            *old_root
        } else {
            let (first, rest) = path.split_first().ok_or(ProofError::MalformedProof)?;
            path = rest;
            *first
        };

        let mut f_n = old - 1;
        let mut s_n = new - 1;
        while f_n & 1 == 1 {
            f_n >>= 1;
            s_n >>= 1;
        }
        let mut f_r = seed;
        let mut s_r = seed;
        for node in path {
            if s_n == 0 {
                return Err(ProofError::MalformedProof);
            }
            if f_n & 1 == 1 || f_n == s_n {
                f_r = node_hash(node, &f_r);
                s_r = node_hash(node, &s_r);
                while f_n & 1 == 0 && f_n != 0 {
                    f_n >>= 1;
                    s_n >>= 1;
                }
            } else {
                s_r = node_hash(&s_r, node);
            }
            f_n >>= 1;
            s_n >>= 1;
        }
        if s_n != 0 {
            return Err(ProofError::MalformedProof);
        }
        if f_r != *old_root || s_r != *new_root {
            return Err(ProofError::RootMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(n: u64) -> MerkleTree {
        let mut tree = MerkleTree::new();
        for i in 0..n {
            tree.push(leaf_hash(format!("leaf-{i}").as_bytes()));
        }
        tree
    }

    #[test]
    fn known_root_vectors() {
        assert_eq!(
            MerkleTree::new().root().to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let mut single = MerkleTree::new();
        single.push(leaf_hash(b""));
        assert_eq!(
            single.root().to_string(),
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
        );
    }

    #[test]
    fn inclusion_proofs_verify_for_every_leaf_and_size() {
        let full = tree(33);
        for size in 1..=33 {
            let root = full.root_at(size).unwrap();
            for index in 0..size {
                let proof = full.inclusion_proof(index, size).unwrap();
                let leaf = full.leaf(index).unwrap();
                assert_eq!(proof.verify(&leaf, &root), Ok(()), "{index}/{size}");
            }
        }
    }

    #[test]
    fn inclusion_proof_rejects_wrong_leaf_root_index_and_path() {
        let full = tree(10);
        let root = full.root();
        let proof = full.inclusion_proof(3, 10).unwrap();
        let leaf = full.leaf(3).unwrap();

        assert_eq!(
            proof.verify(&full.leaf(4).unwrap(), &root),
            Err(ProofError::RootMismatch)
        );
        assert_eq!(
            proof.verify(&leaf, &full.root_at(9).unwrap()),
            Err(ProofError::RootMismatch)
        );

        let mut wrong_index = proof.clone();
        wrong_index.leaf_index = 2;
        assert!(wrong_index.verify(&leaf, &root).is_err());

        let mut truncated = proof.clone();
        truncated.path.pop();
        assert!(truncated.verify(&leaf, &root).is_err());

        let mut extended = proof.clone();
        extended.path.push(leaf);
        assert_eq!(
            extended.verify(&leaf, &root),
            Err(ProofError::MalformedProof)
        );

        let mut flipped = proof.clone();
        flipped.path[1] = leaf_hash(b"forged");
        assert_eq!(flipped.verify(&leaf, &root), Err(ProofError::RootMismatch));

        let mut out_of_range = proof;
        out_of_range.leaf_index = 10;
        assert!(matches!(
            out_of_range.verify(&leaf, &root),
            Err(ProofError::IndexOutOfRange { .. })
        ));
    }

    #[test]
    fn consistency_proofs_verify_for_all_size_pairs() {
        let full = tree(33);
        for new in 0..=33 {
            let new_root = full.root_at(new).unwrap();
            for old in 0..=new {
                let old_root = full.root_at(old).unwrap();
                let proof = full.consistency_proof(old, new).unwrap();
                assert_eq!(proof.verify(&old_root, &new_root), Ok(()), "{old}->{new}");
            }
        }
    }

    #[test]
    fn consistency_proof_detects_rewritten_history() {
        let honest = tree(12);
        let mut forked = MerkleTree::new();
        for i in 0..12u64 {
            let data = if i == 2 {
                "rewritten".to_string()
            } else {
                format!("leaf-{i}")
            };
            forked.push(leaf_hash(data.as_bytes()));
        }
        for old in 3..12 {
            let honest_old = honest.root_at(old).unwrap();
            let proof = forked.consistency_proof(old, 12).unwrap();
            assert!(
                proof.verify(&honest_old, &forked.root()).is_err(),
                "fork must be detected from old size {old}"
            );
        }
    }

    #[test]
    fn consistency_proof_rejects_tampered_paths() {
        let full = tree(20);
        let proof = full.consistency_proof(7, 20).unwrap();
        let (old_root, new_root) = (full.root_at(7).unwrap(), full.root());

        let mut tampered = proof.clone();
        tampered.path[0] = leaf_hash(b"x");
        assert!(tampered.verify(&old_root, &new_root).is_err());

        let mut short = proof.clone();
        short.path.pop();
        assert!(short.verify(&old_root, &new_root).is_err());

        let mut resized = proof;
        resized.new_size = 40;
        assert!(resized.verify(&old_root, &new_root).is_err());

        let same = full.consistency_proof(20, 20).unwrap();
        assert_eq!(
            same.verify(&new_root, &old_root),
            Err(ProofError::RootMismatch)
        );
    }

    #[test]
    fn out_of_range_requests_fail() {
        let full = tree(4);
        assert!(full.inclusion_proof(4, 4).is_err());
        assert!(full.inclusion_proof(0, 5).is_err());
        assert!(full.consistency_proof(3, 2).is_err());
        assert!(full.consistency_proof(1, 5).is_err());
    }
}
