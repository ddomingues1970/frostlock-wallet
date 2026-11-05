use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    errors::{ErrorCode, Result, WalletError},
    policy::DescriptorPolicy,
};

pub const SECRET_FORMAT: &str = "frostlock-wallet-secret";
pub const SECRET_FORMAT_VERSION: u16 = 1;

/// Secret text with redacted Debug output and best-effort Drop cleanup.
///
/// The payload must only be serialized inside the GPG integration. It must
/// never be written directly to a file, log, argument, or environment
/// variable.
pub struct SecretText(String);

impl SecretText {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl Drop for SecretText {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Serialize for SecretText {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretText {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::new)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WalletSecretV1 {
    pub format: String,
    pub version: u16,
    pub network: String,
    pub policy: DescriptorPolicy,
    pub gpg_recipient_fingerprint: String,
    pub mnemonic: SecretText,
    #[serde(default)]
    pub bip39_passphrase: Option<SecretText>,
}

impl WalletSecretV1 {
    pub fn new(
        network: String,
        policy: DescriptorPolicy,
        gpg_recipient_fingerprint: String,
        mnemonic: String,
    ) -> Self {
        Self {
            format: SECRET_FORMAT.to_owned(),
            version: SECRET_FORMAT_VERSION,
            network,
            policy,
            gpg_recipient_fingerprint,
            mnemonic: SecretText::new(mnemonic),
            bip39_passphrase: None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.format != SECRET_FORMAT || self.version != SECRET_FORMAT_VERSION {
            return Err(WalletError::new(
                ErrorCode::InvalidSecretFormat,
                "incompatible secret format",
            ));
        }

        if self.network.is_empty() || self.mnemonic.expose().is_empty() {
            return Err(WalletError::new(
                ErrorCode::InvalidSecretFormat,
                "incomplete secret payload",
            ));
        }

        if self.gpg_recipient_fingerprint.len() != 40
            || !self
                .gpg_recipient_fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(WalletError::new(
                ErrorCode::InvalidSecretFormat,
                "invalid GPG fingerprint",
            ));
        }

        self.policy.validate()
    }
}

pub fn serialize_for_gpg(secret: &WalletSecretV1) -> Result<Zeroizing<Vec<u8>>> {
    secret.validate()?;
    serde_json::to_vec(secret).map(Zeroizing::new).map_err(|_| {
        WalletError::new(
            ErrorCode::InvalidSecretFormat,
            "unable to serialize secret payload",
        )
    })
}

pub fn deserialize_from_gpg(payload: &[u8]) -> Result<WalletSecretV1> {
    let secret: WalletSecretV1 = serde_json::from_slice(payload).map_err(|_| {
        WalletError::new(
            ErrorCode::InvalidSecretFormat,
            "GPG payload is not a valid frostlock-wallet-secret-v1",
        )
    })?;
    secret.validate()?;
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Network, policy::DescriptorPolicy};

    #[test]
    fn round_trip_preserves_schema_without_exposing_debug_secret() {
        let secret = WalletSecretV1::new(
            "regtest".to_owned(),
            DescriptorPolicy::bip84(Network::Regtest, 0),
            "0123456789abcdef0123456789abcdef01234567".to_owned(),
            "test mnemonic that must never appear in Debug".to_owned(),
        );

        let encoded = serialize_for_gpg(&secret).expect("valid secret");
        let decoded = deserialize_from_gpg(&encoded).expect("valid payload");
        let debug = format!("{decoded:?}");

        assert_eq!(decoded.network, "regtest");
        assert!(!debug.contains("test mnemonic"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn rejects_wrong_version() {
        let payload = br#"{
            "format":"frostlock-wallet-secret",
            "version":99,
            "network":"regtest",
            "policy":{"purpose":84,"coin_type":1,"account":0},
            "gpg_recipient_fingerprint":"0123456789abcdef0123456789abcdef01234567",
            "mnemonic":"secret"
        }"#;

        let error = deserialize_from_gpg(payload).expect_err("wrong version must fail");

        assert_eq!(error.code(), ErrorCode::InvalidSecretFormat);
    }
}
