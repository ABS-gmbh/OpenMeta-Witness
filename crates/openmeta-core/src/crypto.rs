use std::fmt;
use std::str::FromStr;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};

use crate::Error;

macro_rules! hex_serde {
    ($ty:ty) => {
        impl Serialize for $ty {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.to_string())
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let s = String::deserialize(deserializer)?;
                s.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

fn decode_fixed<const N: usize>(s: &str, what: &'static str) -> Result<[u8; N], Error> {
    let bytes = hex::decode(s).map_err(|_| Error::InvalidHex(what))?;
    bytes.try_into().map_err(|_| Error::InvalidHex(what))
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest([u8; 32]);

impl Digest {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn sha256(data: &[u8]) -> Self {
        Self(Sha256::digest(data).into())
    }

    pub fn tagged(tag: &str, data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update((tag.len() as u64).to_be_bytes());
        hasher.update(tag.as_bytes());
        hasher.update(data);
        Self(hasher.finalize().into())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn short(&self) -> String {
        hex::encode(&self.0[..6])
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({self})")
    }
}

impl FromStr for Digest {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        decode_fixed(s, "SHA-256 digest").map(Self)
    }
}

hex_serde!(Digest);

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(VerifyingKey);

impl PublicKey {
    pub fn fingerprint(&self) -> Digest {
        Digest::tagged("openmeta/public-key", self.0.as_bytes())
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
        self.0
            .verify_strict(message, &signature.0)
            .map_err(|_| Error::InvalidSignature)
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0.as_bytes()))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({self})")
    }
}

impl FromStr for PublicKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = decode_fixed(s, "Ed25519 public key")?;
        VerifyingKey::from_bytes(&bytes)
            .map(Self)
            .map_err(|_| Error::InvalidPublicKey)
    }
}

hex_serde!(PublicKey);

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature(ed25519_dalek::Signature);

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0.to_bytes()))
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({self})")
    }
}

impl FromStr for Signature {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes: [u8; 64] = decode_fixed(s, "Ed25519 signature")?;
        Ok(Self(ed25519_dalek::Signature::from_bytes(&bytes)))
    }
}

hex_serde!(Signature);

pub struct Keypair(SigningKey);

impl Keypair {
    pub fn generate() -> Self {
        Self(SigningKey::generate(&mut OsRng))
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(SigningKey::from_bytes(&seed))
    }

    pub fn from_secret_hex(s: &str) -> Result<Self, Error> {
        decode_fixed(s.trim(), "Ed25519 secret key").map(Self::from_seed)
    }

    pub fn secret_hex(&self) -> String {
        hex::encode(self.0.to_bytes())
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.0.sign(message))
    }
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Keypair(public: {}, secret: <redacted>)",
            self.public_key()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_roundtrip_and_rejection() {
        let key = Keypair::from_seed([7; 32]);
        let sig = key.sign(b"message");
        assert_eq!(key.public_key().verify(b"message", &sig), Ok(()));
        assert_eq!(
            key.public_key().verify(b"messagf", &sig),
            Err(Error::InvalidSignature)
        );
        let other = Keypair::from_seed([8; 32]);
        assert_eq!(
            other.public_key().verify(b"message", &sig),
            Err(Error::InvalidSignature)
        );
    }

    #[test]
    fn hex_encodings_roundtrip() {
        let key = Keypair::from_seed([1; 32]);
        let pk: PublicKey = key.public_key().to_string().parse().unwrap();
        assert_eq!(pk, key.public_key());
        let sig = key.sign(b"x");
        let parsed: Signature = sig.to_string().parse().unwrap();
        assert_eq!(parsed, sig);
        let restored = Keypair::from_secret_hex(&key.secret_hex()).unwrap();
        assert_eq!(restored.public_key(), key.public_key());
    }

    #[test]
    fn debug_output_never_contains_secret() {
        let key = Keypair::from_seed([9; 32]);
        let debug = format!("{key:?}");
        assert!(!debug.contains(&key.secret_hex()));
        assert!(debug.contains("redacted"));
    }

    #[test]
    fn tagged_hashes_are_domain_separated() {
        assert_ne!(Digest::tagged("a", b"bc"), Digest::tagged("ab", b"c"));
        assert_ne!(Digest::tagged("a", b"x"), Digest::sha256(b"x"));
    }

    #[test]
    fn malformed_hex_is_rejected() {
        assert!("abc".parse::<Digest>().is_err());
        assert!("zz".repeat(32).parse::<Digest>().is_err());
        assert!("00".repeat(31).parse::<Digest>().is_err());
    }
}
