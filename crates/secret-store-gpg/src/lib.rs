#![forbid(unsafe_code)]
//! GPGME-backed encrypted backup storage for Frostlock Wallet.
//!
//! This adapter never invokes `gpg` through a shell and never writes the
//! plaintext wallet secret to disk. GPGME delegates passphrase handling to the
//! user's configured GPG agent and pinentry.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use frostlock_wallet_core::secret_format::{
    WalletSecretV1, deserialize_from_gpg, serialize_for_gpg,
};
use gpgme::{Context, Data, Key, Protocol};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpgStoreError {
    InvalidFingerprint,
    RecipientNotFound,
    RecipientNotUsable,
    GpgFailure,
    InvalidPayload,
    IoFailure,
    DestinationExists,
    NonUtf8Path,
}

impl std::fmt::Display for GpgStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidFingerprint => "invalid GPG recipient fingerprint",
            Self::RecipientNotFound => "GPG recipient key was not found",
            Self::RecipientNotUsable => "GPG recipient key cannot encrypt",
            Self::GpgFailure => "GPGME operation failed",
            Self::InvalidPayload => "wallet secret payload is invalid",
            Self::IoFailure => "encrypted backup file operation failed",
            Self::DestinationExists => "backup destination already exists",
            Self::NonUtf8Path => "GPG home path is not valid UTF-8",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for GpgStoreError {}

/// A GPGME adapter bound to the default keyring or an explicit GnuPG home.
#[derive(Debug, Clone, Default)]
pub struct GpgSecretStore {
    home_dir: Option<PathBuf>,
}

impl GpgSecretStore {
    pub fn new(home_dir: Option<PathBuf>) -> Result<Self, GpgStoreError> {
        if let Some(path) = &home_dir {
            if !path.is_dir() {
                return Err(GpgStoreError::IoFailure);
            }
        }

        let gpgme = gpgme::init();
        if !gpgme.check_version("1.18.0") {
            return Err(GpgStoreError::GpgFailure);
        }

        Ok(Self { home_dir })
    }

    pub fn encrypt(
        &self,
        secret: &WalletSecretV1,
        recipient_fingerprint: &str,
    ) -> Result<Vec<u8>, GpgStoreError> {
        let fingerprint = normalize_fingerprint(recipient_fingerprint)?;
        let plaintext = serialize_for_gpg(secret).map_err(|_| GpgStoreError::InvalidPayload)?;
        let plaintext_bytes: &[u8] = plaintext.as_ref();
        let mut context = self.context()?;
        let key = recipient_key(&mut context, &fingerprint)?;
        let mut ciphertext = Vec::new();

        context
            .encrypt(Some(&key), plaintext_bytes, &mut ciphertext)
            .map_err(|_| GpgStoreError::GpgFailure)?;

        if ciphertext.is_empty() {
            return Err(GpgStoreError::GpgFailure);
        }

        Ok(ciphertext)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<WalletSecretV1, GpgStoreError> {
        if ciphertext.is_empty() {
            return Err(GpgStoreError::InvalidPayload);
        }

        let mut context = self.context()?;
        let mut encrypted = Data::from_bytes(ciphertext).map_err(|_| GpgStoreError::GpgFailure)?;
        let mut plaintext = Vec::new();
        context
            .decrypt(&mut encrypted, &mut plaintext)
            .map_err(|_| GpgStoreError::GpgFailure)?;
        let plaintext = Zeroizing::new(plaintext);

        deserialize_from_gpg(&plaintext).map_err(|_| GpgStoreError::InvalidPayload)
    }

    /// Encrypts the secret and atomically creates a mode-0600 backup file.
    /// Existing destinations are never overwritten by this method.
    pub fn backup_to(
        &self,
        secret: &WalletSecretV1,
        recipient_fingerprint: &str,
        destination: &Path,
    ) -> Result<(), GpgStoreError> {
        let ciphertext = self.encrypt(secret, recipient_fingerprint)?;
        let parent = destination.parent().unwrap_or_else(|| Path::new("."));
        if !parent.is_dir() {
            return Err(GpgStoreError::IoFailure);
        }

        let mut temporary = NamedTempFile::new_in(parent).map_err(|_| GpgStoreError::IoFailure)?;
        temporary
            .write_all(&ciphertext)
            .map_err(|_| GpgStoreError::IoFailure)?;
        temporary
            .as_file()
            .sync_all()
            .map_err(|_| GpgStoreError::IoFailure)?;
        temporary.persist_noclobber(destination).map_err(|error| {
            if error.error.kind() == std::io::ErrorKind::AlreadyExists {
                GpgStoreError::DestinationExists
            } else {
                GpgStoreError::IoFailure
            }
        })?;

        Ok(())
    }

    pub fn restore_from(&self, backup: &Path) -> Result<WalletSecretV1, GpgStoreError> {
        let ciphertext = fs::read(backup).map_err(|_| GpgStoreError::IoFailure)?;
        self.decrypt(&ciphertext)
    }

    fn context(&self) -> Result<Context, GpgStoreError> {
        let mut context =
            Context::from_protocol(Protocol::OpenPgp).map_err(|_| GpgStoreError::GpgFailure)?;
        if let Some(home_dir) = &self.home_dir {
            let home_dir = home_dir.to_str().ok_or(GpgStoreError::NonUtf8Path)?;
            context
                .set_engine_home_dir(home_dir)
                .map_err(|_| GpgStoreError::GpgFailure)?;
        }
        context.set_armor(false);
        context.set_text_mode(false);
        Ok(context)
    }
}

fn normalize_fingerprint(fingerprint: &str) -> Result<String, GpgStoreError> {
    let fingerprint = fingerprint.trim();
    if fingerprint.len() != 40 || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(GpgStoreError::InvalidFingerprint);
    }
    Ok(fingerprint.to_ascii_lowercase())
}

fn recipient_key(context: &mut Context, fingerprint: &str) -> Result<Key, GpgStoreError> {
    let key = context
        .get_key(fingerprint)
        .map_err(|_| GpgStoreError::RecipientNotFound)?;
    let key_fingerprint = key
        .fingerprint()
        .map_err(|_| GpgStoreError::RecipientNotFound)?;

    if !key_fingerprint.eq_ignore_ascii_case(fingerprint)
        || key.is_bad()
        || key.is_revoked()
        || key.is_expired()
        || key.is_disabled()
        || key.is_invalid()
        || !key.can_encrypt()
    {
        return Err(GpgStoreError::RecipientNotUsable);
    }

    Ok(key)
}

#[cfg(test)]
mod tests {
    use std::{process::Command, str};

    use frostlock_wallet_core::{Network, policy::DescriptorPolicy, secret_format::WalletSecretV1};
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn gpgme_round_trip_uses_an_isolated_keyring() {
        let home = tempdir().expect("temporary GPG home");
        let home_path = home.path();
        #[cfg(unix)]
        std::fs::set_permissions(
            home_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("restrict temporary GPG home permissions");
        run_gpg(
            home_path,
            [
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-generate-key",
                "Frostlock Test <frostlock-test@example.invalid>",
                "rsa2048",
                "encr",
                "0",
            ],
        );
        let fingerprint = key_fingerprint(home_path);
        let store = GpgSecretStore::new(Some(home_path.to_path_buf())).expect("GPGME store");
        let secret = WalletSecretV1::new(
            "regtest".to_owned(),
            DescriptorPolicy::bip84(Network::Regtest, 0),
            fingerprint.clone(),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                .to_owned(),
        );

        let ciphertext = store
            .encrypt(&secret, &fingerprint)
            .expect("encrypted payload");
        assert!(
            !ciphertext
                .windows(b"abandon".len())
                .any(|window| window == b"abandon")
        );

        let restored = store.decrypt(&ciphertext).expect("decrypted payload");
        assert_eq!(restored.network, "regtest");
        assert_eq!(restored.mnemonic.expose(), secret.mnemonic.expose());
    }

    fn run_gpg(home: &Path, arguments: impl IntoIterator<Item = &'static str>) {
        let status = Command::new("gpg")
            .arg("--homedir")
            .arg(home)
            .args(arguments)
            .status()
            .expect("gpg must be installed for the GPGME integration test");
        assert!(status.success(), "gpg test key generation failed");
    }

    fn key_fingerprint(home: &Path) -> String {
        let output = Command::new("gpg")
            .arg("--homedir")
            .arg(home)
            .args(["--batch", "--with-colons", "--list-keys"])
            .output()
            .expect("gpg key listing");
        assert!(output.status.success(), "gpg test key listing failed");
        str::from_utf8(&output.stdout)
            .expect("gpg output is UTF-8")
            .lines()
            .find_map(|line| {
                let fields: Vec<_> = line.split(':').collect();
                (fields.first() == Some(&"fpr")).then(|| fields[9].to_owned())
            })
            .expect("test key fingerprint")
    }
}
