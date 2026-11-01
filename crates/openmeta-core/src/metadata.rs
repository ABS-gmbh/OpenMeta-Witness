use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::canonical::to_canonical_json;
use crate::{Digest, Error, Keypair, PublicKey, Purl, Signature};

const METADATA_HASH_TAG: &str = "openmeta/metadata/v1";
const METADATA_SIGNATURE_CONTEXT: &[u8] = b"openmeta/metadata-signature/v1\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Timestamp(u64);

impl Timestamp {
    pub const fn from_unix_seconds(seconds: u64) -> Self {
        Self(seconds)
    }

    pub fn now() -> Self {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();
        Self(seconds)
    }

    pub fn unix_seconds(&self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceReference {
    pub repository: String,
    pub revision: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublisherIdentity {
    pub name: String,
    pub public_key: PublicKey,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct License {
    pub spdx_expression: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyRef {
    pub purl: Purl,
    pub requirement: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VulnerabilityStatus {
    Affected,
    NotAffected,
    Fixed,
    UnderInvestigation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VulnerabilityRef {
    pub id: String,
    pub status: VulnerabilityStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageMetadata {
    pub purl: Purl,
    pub name: String,
    pub version: String,
    pub source: SourceReference,
    pub artifact_digest: Digest,
    pub publisher: PublisherIdentity,
    pub published_at: Timestamp,
    pub license: License,
    pub dependencies: Vec<DependencyRef>,
    pub vulnerabilities: Vec<VulnerabilityRef>,
    pub revision: u32,
    pub previous_revision: Option<Digest>,
}

fn invalid(message: impl Into<String>) -> Error {
    Error::InvalidMetadata(message.into())
}

fn is_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
}

impl PackageMetadata {
    pub fn validate(&self) -> Result<(), Error> {
        if self.purl.name() != self.name {
            return Err(invalid("package name does not match the package URL"));
        }
        if self.purl.version() != Some(self.version.as_str()) {
            return Err(invalid("package version does not match the package URL"));
        }
        if !self.source.repository.contains("://") {
            return Err(invalid("source repository must be a URL"));
        }
        if self.source.revision.trim().is_empty() {
            return Err(invalid("source revision must not be empty"));
        }
        if !is_identifier(&self.publisher.name) {
            return Err(invalid("publisher name must be a non-empty identifier"));
        }
        if self.published_at.unix_seconds() == 0 {
            return Err(invalid("publication timestamp must be set"));
        }
        let license = &self.license.spdx_expression;
        if license.trim().is_empty()
            || !license
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || " -.+()".contains(c))
        {
            return Err(invalid("license must be an SPDX expression"));
        }

        let mut seen = BTreeSet::new();
        for dependency in &self.dependencies {
            if dependency.purl.without_version() == self.purl.without_version() {
                return Err(invalid("a package cannot depend on itself"));
            }
            if !seen.insert(dependency.purl.to_string()) {
                return Err(invalid(format!("duplicate dependency {}", dependency.purl)));
            }
        }
        let mut seen = BTreeSet::new();
        for vulnerability in &self.vulnerabilities {
            if !is_identifier(&vulnerability.id) {
                return Err(invalid(format!(
                    "invalid vulnerability identifier `{}`",
                    vulnerability.id
                )));
            }
            if !seen.insert(vulnerability.id.as_str()) {
                return Err(invalid(format!(
                    "duplicate vulnerability {}",
                    vulnerability.id
                )));
            }
        }

        match (self.revision, self.previous_revision) {
            (0, _) => Err(invalid("revision numbers start at 1")),
            (1, Some(_)) => Err(invalid("revision 1 cannot reference a previous revision")),
            (2.., None) => Err(invalid(
                "later revisions must reference the previous revision",
            )),
            _ => Ok(()),
        }
    }

    pub fn normalized(&self) -> Self {
        let mut normalized = self.clone();
        normalized
            .dependencies
            .sort_by(|a, b| a.purl.to_string().cmp(&b.purl.to_string()));
        normalized.vulnerabilities.sort_by(|a, b| a.id.cmp(&b.id));
        normalized
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        to_canonical_json(&self.normalized())
            .expect("package metadata contains only canonical JSON types")
    }

    pub fn content_hash(&self) -> Digest {
        Digest::tagged(METADATA_HASH_TAG, &self.canonical_bytes())
    }

    fn signing_message(&self) -> Vec<u8> {
        let mut message = METADATA_SIGNATURE_CONTEXT.to_vec();
        message.extend_from_slice(&self.canonical_bytes());
        message
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRecord {
    pub metadata: PackageMetadata,
    pub signature: Signature,
}

impl SignedRecord {
    pub fn sign(metadata: PackageMetadata, key: &Keypair) -> Result<Self, Error> {
        metadata.validate()?;
        if key.public_key() != metadata.publisher.public_key {
            return Err(Error::PublisherKeyMismatch(metadata.publisher.name));
        }
        let metadata = metadata.normalized();
        let signature = key.sign(&metadata.signing_message());
        Ok(Self {
            metadata,
            signature,
        })
    }

    pub fn verify(&self) -> Result<(), Error> {
        self.metadata.validate()?;
        self.metadata
            .publisher
            .public_key
            .verify(&self.metadata.signing_message(), &self.signature)
    }

    pub fn verify_publisher(&self, expected: &PublicKey) -> Result<(), Error> {
        self.verify()?;
        let actual = &self.metadata.publisher.public_key;
        if actual != expected {
            return Err(Error::UnexpectedPublisher {
                expected: expected.to_string(),
                actual: actual.to_string(),
            });
        }
        Ok(())
    }

    pub fn content_hash(&self) -> Digest {
        self.metadata.content_hash()
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let normalized = Self {
            metadata: self.metadata.normalized(),
            signature: self.signature,
        };
        to_canonical_json(&normalized).expect("signed records contain only canonical JSON types")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(key: &Keypair) -> PackageMetadata {
        PackageMetadata {
            purl: "pkg:cargo/examplelib@1.0.0".parse().unwrap(),
            name: "examplelib".into(),
            version: "1.0.0".into(),
            source: SourceReference {
                repository: "https://git.example.org/examplelib.git".into(),
                revision: "4f2a9c1".into(),
            },
            artifact_digest: Digest::sha256(b"examplelib-1.0.0.crate"),
            publisher: PublisherIdentity {
                name: "publisher-a".into(),
                public_key: key.public_key(),
            },
            published_at: Timestamp::from_unix_seconds(1_767_225_600),
            license: License {
                spdx_expression: "MIT OR Apache-2.0".into(),
            },
            dependencies: vec![
                DependencyRef {
                    purl: "pkg:cargo/serde@1.0.210".parse().unwrap(),
                    requirement: Some("^1.0".into()),
                },
                DependencyRef {
                    purl: "pkg:cargo/log@0.4.22".parse().unwrap(),
                    requirement: None,
                },
            ],
            vulnerabilities: vec![VulnerabilityRef {
                id: "CVE-2026-0001".into(),
                status: VulnerabilityStatus::NotAffected,
            }],
            revision: 1,
            previous_revision: None,
        }
    }

    #[test]
    fn signed_record_verifies() {
        let key = Keypair::from_seed([1; 32]);
        let record = SignedRecord::sign(sample(&key), &key).unwrap();
        assert_eq!(record.verify(), Ok(()));
        assert_eq!(record.verify_publisher(&key.public_key()), Ok(()));
    }

    #[test]
    fn modified_fields_are_rejected() {
        let key = Keypair::from_seed([1; 32]);
        let record = SignedRecord::sign(sample(&key), &key).unwrap();

        let mut license = record.clone();
        license.metadata.license.spdx_expression = "GPL-3.0-only".into();
        assert_eq!(license.verify(), Err(Error::InvalidSignature));

        let mut digest = record.clone();
        digest.metadata.artifact_digest = Digest::sha256(b"backdoored");
        assert_eq!(digest.verify(), Err(Error::InvalidSignature));

        let mut vulns = record.clone();
        vulns.metadata.vulnerabilities.clear();
        assert_eq!(vulns.verify(), Err(Error::InvalidSignature));
    }

    #[test]
    fn invalid_signature_is_rejected() {
        let key = Keypair::from_seed([1; 32]);
        let mut record = SignedRecord::sign(sample(&key), &key).unwrap();
        record.signature = key.sign(b"something else");
        assert_eq!(record.verify(), Err(Error::InvalidSignature));
    }

    #[test]
    fn substituted_publisher_key_is_detected() {
        let key = Keypair::from_seed([1; 32]);
        let attacker = Keypair::from_seed([2; 32]);
        let mut metadata = sample(&key);
        metadata.publisher.public_key = attacker.public_key();
        let forged = SignedRecord::sign(metadata, &attacker).unwrap();
        assert_eq!(forged.verify(), Ok(()));
        assert!(matches!(
            forged.verify_publisher(&key.public_key()),
            Err(Error::UnexpectedPublisher { .. })
        ));
    }

    #[test]
    fn signing_with_foreign_key_fails() {
        let key = Keypair::from_seed([1; 32]);
        let other = Keypair::from_seed([3; 32]);
        assert_eq!(
            SignedRecord::sign(sample(&key), &other),
            Err(Error::PublisherKeyMismatch("publisher-a".into()))
        );
    }

    #[test]
    fn hashing_is_deterministic_and_order_independent() {
        let key = Keypair::from_seed([1; 32]);
        let a = sample(&key);
        let mut b = a.clone();
        b.dependencies.reverse();
        assert_eq!(a.content_hash(), a.clone().content_hash());
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
        assert_eq!(a.content_hash(), b.content_hash());

        let json = serde_json::to_string_pretty(&b).unwrap();
        let parsed: PackageMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.content_hash(), a.content_hash());

        let mut c = a.clone();
        c.revision = 2;
        c.previous_revision = Some(a.content_hash());
        assert_ne!(a.content_hash(), c.content_hash());
    }

    #[test]
    fn record_survives_json_roundtrip_with_reordered_dependencies() {
        let key = Keypair::from_seed([1; 32]);
        let record = SignedRecord::sign(sample(&key), &key).unwrap();
        let mut reordered = record.clone();
        reordered.metadata.dependencies.reverse();
        assert_eq!(reordered.verify(), Ok(()));
        assert_eq!(reordered.canonical_bytes(), record.canonical_bytes());
        let parsed: SignedRecord = serde_json::from_slice(&record.canonical_bytes()).unwrap();
        assert_eq!(parsed, record);
    }

    #[test]
    fn validation_rejects_inconsistent_metadata() {
        let key = Keypair::from_seed([1; 32]);
        let mut wrong_version = sample(&key);
        wrong_version.version = "1.0.1".into();
        assert!(wrong_version.validate().is_err());

        let mut duplicate = sample(&key);
        duplicate
            .dependencies
            .push(duplicate.dependencies[0].clone());
        assert!(duplicate.validate().is_err());

        let mut orphan_revision = sample(&key);
        orphan_revision.revision = 2;
        assert!(orphan_revision.validate().is_err());

        let mut bad_license = sample(&key);
        bad_license.license.spdx_expression = "MIT; rm -rf".into();
        assert!(bad_license.validate().is_err());
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let key = Keypair::from_seed([1; 32]);
        let mut value = serde_json::to_value(sample(&key)).unwrap();
        value["unsigned_note"] = serde_json::json!("trust me");
        assert!(serde_json::from_value::<PackageMetadata>(value).is_err());
    }
}
