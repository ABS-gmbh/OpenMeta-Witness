use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use openmeta_core::{Keypair, PublicKey};

use crate::StoreError;

pub struct Keystore {
    dir: PathBuf,
}

fn validate_name(name: &str) -> Result<(), StoreError> {
    let valid = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if valid {
        Ok(())
    } else {
        Err(StoreError::InvalidKeyName(name.to_string()))
    }
}

#[cfg(unix)]
fn restrict_permissions(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn restrict_permissions(_options: &mut OpenOptions) {}

impl Keystore {
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, StoreError> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self { dir })
    }

    fn secret_path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.secret"))
    }

    fn public_path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.pub"))
    }

    pub fn create(&self, name: &str) -> Result<PublicKey, StoreError> {
        let keypair = Keypair::generate();
        self.import(name, &keypair)?;
        Ok(keypair.public_key())
    }

    pub fn import(&self, name: &str, keypair: &Keypair) -> Result<(), StoreError> {
        validate_name(name)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        restrict_permissions(&mut options);
        let mut secret = match options.open(self.secret_path(name)) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(StoreError::KeyExists(name.to_string()));
            }
            Err(e) => return Err(e.into()),
        };
        secret.write_all(keypair.secret_hex().as_bytes())?;
        secret.sync_all()?;
        fs::write(self.public_path(name), keypair.public_key().to_string())?;
        Ok(())
    }

    pub fn load(&self, name: &str) -> Result<Keypair, StoreError> {
        validate_name(name)?;
        let secret = match fs::read_to_string(self.secret_path(name)) {
            Ok(secret) => secret,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(StoreError::KeyNotFound(name.to_string()));
            }
            Err(e) => return Err(e.into()),
        };
        let keypair = Keypair::from_secret_hex(&secret)?;
        if keypair.public_key() != self.public_key(name)? {
            return Err(StoreError::Corrupted(format!(
                "public key file for `{name}` does not match its secret key"
            )));
        }
        Ok(keypair)
    }

    pub fn public_key(&self, name: &str) -> Result<PublicKey, StoreError> {
        validate_name(name)?;
        match fs::read_to_string(self.public_path(name)) {
            Ok(text) => Ok(text.trim().parse()?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(StoreError::KeyNotFound(name.to_string()))
            }
            Err(e) => Err(e.into()),
        }
    }

    pub fn list(&self) -> Result<Vec<(String, PublicKey)>, StoreError> {
        let mut keys = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let path = entry?.path();
            if path.extension().is_some_and(|ext| ext == "pub")
                && let Some(name) = path.file_stem().and_then(|s| s.to_str())
            {
                keys.push((name.to_string(), self.public_key(name)?));
            }
        }
        keys.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_roundtrip_and_are_not_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let store = Keystore::open(dir.path().join("keys")).unwrap();
        let public = store.create("publisher-a").unwrap();
        assert_eq!(store.load("publisher-a").unwrap().public_key(), public);
        assert_eq!(store.public_key("publisher-a").unwrap(), public);
        assert!(matches!(
            store.create("publisher-a"),
            Err(StoreError::KeyExists(_))
        ));
        assert_eq!(store.load("publisher-a").unwrap().public_key(), public);
        assert!(matches!(
            store.load("nobody"),
            Err(StoreError::KeyNotFound(_))
        ));
        assert!(matches!(
            store.create("../escape"),
            Err(StoreError::InvalidKeyName(_))
        ));
        assert_eq!(store.list().unwrap(), vec![("publisher-a".into(), public)]);
    }

    #[cfg(unix)]
    #[test]
    fn secret_keys_are_private_files() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let store = Keystore::open(dir.path()).unwrap();
        store.create("witness-a").unwrap();
        let mode = fs::metadata(dir.path().join("witness-a.secret"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn mismatched_public_key_file_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let store = Keystore::open(dir.path()).unwrap();
        store.create("a").unwrap();
        let other = store.create("b").unwrap();
        fs::write(dir.path().join("a.pub"), other.to_string()).unwrap();
        assert!(matches!(store.load("a"), Err(StoreError::Corrupted(_))));
    }
}
