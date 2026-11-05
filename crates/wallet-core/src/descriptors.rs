use crate::{
    errors::{ErrorCode, Result, WalletError},
    policy::DescriptorPolicy,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keychain {
    External,
    Internal,
}

impl Keychain {
    pub const fn branch(self) -> u32 {
        match self {
            Self::External => 0,
            Self::Internal => 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicDescriptorSet {
    pub external: String,
    pub internal: String,
}

/// Builds public BIP84 descriptors.
///
/// The `xpub` is accepted as public text at this layer, while full
/// cryptographic validation will be performed by BDK when loading the wallet.
/// Private keys are rejected to prevent signing material from reaching the
/// public database by mistake.
pub fn public_descriptors(
    policy: DescriptorPolicy,
    fingerprint: &str,
    xpub: &str,
) -> Result<PublicDescriptorSet> {
    policy.validate()?;
    validate_fingerprint(fingerprint)?;
    validate_public_extended_key(xpub)?;

    Ok(PublicDescriptorSet {
        external: descriptor(policy, fingerprint, xpub, Keychain::External),
        internal: descriptor(policy, fingerprint, xpub, Keychain::Internal),
    })
}

fn descriptor(
    policy: DescriptorPolicy,
    fingerprint: &str,
    xpub: &str,
    keychain: Keychain,
) -> String {
    format!(
        "wpkh([{fingerprint}/{purpose}'/{coin_type}'/{account}']{xpub}/{branch}/*)",
        fingerprint = fingerprint.to_ascii_lowercase(),
        purpose = policy.purpose,
        coin_type = policy.coin_type,
        account = policy.account,
        branch = keychain.branch(),
    )
}

fn validate_fingerprint(fingerprint: &str) -> Result<()> {
    let is_hex = fingerprint.len() == 8 && fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit());

    if is_hex {
        Ok(())
    } else {
        Err(WalletError::new(
            ErrorCode::InvalidFingerprint,
            "fingerprint must contain exactly 8 hexadecimal digits",
        ))
    }
}

fn validate_public_extended_key(xpub: &str) -> Result<()> {
    let trimmed = xpub.trim();
    let has_private_prefix = ["xprv", "tprv", "uprv", "vprv"]
        .iter()
        .any(|prefix| trimmed.starts_with(prefix));

    if trimmed.is_empty() || trimmed.contains(char::is_whitespace) {
        return Err(WalletError::new(
            ErrorCode::InvalidPublicKey,
            "xpub cannot be empty or contain whitespace",
        ));
    }

    if has_private_prefix {
        return Err(WalletError::new(
            ErrorCode::SecretInPublicDescriptor,
            "private keys cannot be used in public descriptors",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Network, policy::DescriptorPolicy};

    const XPUB: &str = "tpub-public-test-key";

    #[test]
    fn creates_external_and_internal_descriptors() {
        let policy = DescriptorPolicy::bip84(Network::Regtest, 0);
        let descriptors = public_descriptors(policy, "A1B2C3D4", XPUB).expect("valid policy");

        assert_eq!(
            descriptors.external,
            "wpkh([a1b2c3d4/84'/1'/0']tpub-public-test-key/0/*)"
        );
        assert_eq!(
            descriptors.internal,
            "wpkh([a1b2c3d4/84'/1'/0']tpub-public-test-key/1/*)"
        );
    }

    #[test]
    fn rejects_private_key_in_public_descriptor() {
        let policy = DescriptorPolicy::bip84(Network::Regtest, 0);
        let error = public_descriptors(policy, "a1b2c3d4", "tprv-secret").expect_err("must fail");

        assert_eq!(error.code(), ErrorCode::SecretInPublicDescriptor);
    }
}
