use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid package URL `{input}`: {reason}")]
    InvalidPurl { input: String, reason: &'static str },
    #[error("invalid metadata: {0}")]
    InvalidMetadata(String),
    #[error("invalid hex encoding for {0}")]
    InvalidHex(&'static str),
    #[error("invalid Ed25519 public key")]
    InvalidPublicKey,
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("signing key does not belong to publisher `{0}`")]
    PublisherKeyMismatch(String),
    #[error("record was signed by an unexpected publisher key {actual}, expected {expected}")]
    UnexpectedPublisher { expected: String, actual: String },
    #[error("value cannot be canonically encoded: {0}")]
    NonCanonical(String),
}
