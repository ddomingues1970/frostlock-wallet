use std::str::FromStr;

use bdk_wallet::bitcoin::{
    Address, CompressedPublicKey, Network,
    bip32::{ChildNumber, DerivationPath, Xpriv, Xpub},
    secp256k1::Secp256k1,
};
use bip39::{Language, Mnemonic, WordCount};

use crate::{
    descriptors::Keychain,
    errors::{ErrorCode, Result, WalletError},
    policy::DescriptorPolicy,
    secret_format::SecretText,
};

pub const DEFAULT_MNEMONIC_WORD_COUNT: WordCount = WordCount::Words24;

/// Public BIP32/BIP84 material derived from a mnemonic.
///
/// This type intentionally contains only public recovery metadata. The
/// mnemonic and derived private keys are kept inside short-lived operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedPublicKeys {
    pub network: Network,
    pub policy: DescriptorPolicy,
    pub master_fingerprint: String,
    pub account_xpub: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressComparison {
    pub keychain: Keychain,
    pub index: u32,
    pub mnemonic_address: String,
    pub xpub_address: String,
}

struct SensitiveXpriv(Xpriv);

impl Drop for SensitiveXpriv {
    fn drop(&mut self) {
        self.0.private_key.non_secure_erase();
    }
}

impl AddressComparison {
    pub fn matches(&self) -> bool {
        self.mnemonic_address == self.xpub_address
    }
}

/// Generates a fresh English BIP39 mnemonic using the operating system CSPRNG
/// through the bip39 crate's cryptographic random source.
pub fn generate_mnemonic() -> Result<SecretText> {
    let mnemonic = Mnemonic::generate_in(Language::English, DEFAULT_MNEMONIC_WORD_COUNT)
        .map_err(|_| WalletError::new(ErrorCode::InvalidMnemonic, "unable to generate mnemonic"))?;

    Ok(SecretText::new(mnemonic.to_string()))
}

pub fn parse_mnemonic(mnemonic: &SecretText) -> Result<Mnemonic> {
    Mnemonic::parse_in_normalized(Language::English, mnemonic.expose()).map_err(|_| {
        WalletError::new(
            ErrorCode::InvalidMnemonic,
            "mnemonic is not a valid English BIP39 phrase",
        )
    })
}

pub fn derive_public_keys(
    network: Network,
    policy: DescriptorPolicy,
    mnemonic: &SecretText,
    bip39_passphrase: Option<&SecretText>,
) -> Result<DerivedPublicKeys> {
    let (_, master_fingerprint, account_xpub) =
        derive_account(network, policy, mnemonic, bip39_passphrase)?;

    Ok(DerivedPublicKeys {
        network,
        policy,
        master_fingerprint,
        account_xpub: account_xpub.to_string(),
    })
}

/// Compares addresses derived from the private mnemonic path with addresses
/// derived from the corresponding account xpub. This is the recovery check
/// used by the CLI and the clean-machine test.
pub fn compare_derived_addresses(
    network: Network,
    policy: DescriptorPolicy,
    mnemonic: &SecretText,
    bip39_passphrase: Option<&SecretText>,
    count: u32,
) -> Result<Vec<AddressComparison>> {
    if count == 0 || count > 1000 {
        return Err(WalletError::new(
            ErrorCode::InvalidInput,
            "address comparison count must be between 1 and 1000",
        ));
    }

    let (account_xpriv, _, account_xpub) =
        derive_account(network, policy, mnemonic, bip39_passphrase)?;
    let secp = Secp256k1::new();
    let mut comparisons = Vec::with_capacity(count as usize * 2);

    for keychain in [Keychain::External, Keychain::Internal] {
        for index in 0..count {
            let child_path = DerivationPath::from(vec![
                ChildNumber::Normal {
                    index: keychain.branch(),
                },
                ChildNumber::Normal { index },
            ]);

            let private_child = SensitiveXpriv(
                account_xpriv
                    .0
                    .derive_priv(&secp, &child_path)
                    .map_err(|_| {
                        WalletError::new(ErrorCode::KeyDerivation, "unable to derive child key")
                    })?,
            );
            let public_child = account_xpub.derive_pub(&secp, &child_path).map_err(|_| {
                WalletError::new(ErrorCode::KeyDerivation, "unable to derive child key")
            })?;

            let private_public_key = Xpub::from_priv(&secp, &private_child.0).to_pub();
            let public_public_key = public_child.to_pub();
            let mnemonic_address = p2wpkh_address(private_public_key, network);
            let xpub_address = p2wpkh_address(public_public_key, network);

            comparisons.push(AddressComparison {
                keychain,
                index,
                mnemonic_address,
                xpub_address,
            });
        }
    }

    if comparisons.iter().any(|comparison| !comparison.matches()) {
        return Err(WalletError::new(
            ErrorCode::AddressMismatch,
            "mnemonic and xpub address derivation do not match",
        ));
    }

    Ok(comparisons)
}

fn derive_account(
    network: Network,
    policy: DescriptorPolicy,
    mnemonic: &SecretText,
    bip39_passphrase: Option<&SecretText>,
) -> Result<(SensitiveXpriv, String, Xpub)> {
    policy.validate()?;
    let expected_policy = DescriptorPolicy::bip84(network, policy.account);
    if policy.coin_type != expected_policy.coin_type {
        return Err(WalletError::new(
            ErrorCode::InvalidInput,
            "derivation policy does not match network",
        ));
    }

    let mnemonic = parse_mnemonic(mnemonic)?;
    let passphrase = bip39_passphrase.map_or("", SecretText::expose);
    let seed = zeroize::Zeroizing::new(mnemonic.to_seed(passphrase));
    let secp = Secp256k1::new();
    let master =
        SensitiveXpriv(Xpriv::new_master(network, seed.as_ref()).map_err(|_| {
            WalletError::new(ErrorCode::KeyDerivation, "unable to create master key")
        })?);
    let fingerprint = master.0.fingerprint(&secp).to_string();
    let account_path = DerivationPath::from_str(&format!(
        "m/{}'/{}'/{}'",
        policy.purpose, policy.coin_type, policy.account
    ))
    .map_err(|_| WalletError::new(ErrorCode::KeyDerivation, "invalid account derivation path"))?;
    let account_xpriv =
        SensitiveXpriv(master.0.derive_priv(&secp, &account_path).map_err(|_| {
            WalletError::new(ErrorCode::KeyDerivation, "unable to derive account key")
        })?);
    let account_xpub = Xpub::from_priv(&secp, &account_xpriv.0);

    Ok((account_xpriv, fingerprint, account_xpub))
}

fn p2wpkh_address(public_key: CompressedPublicKey, network: Network) -> String {
    Address::p2wpkh(&public_key, network).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::{KeychainKind, Wallet};

    use crate::{Network, descriptors::public_descriptors, policy::DescriptorPolicy};

    fn test_mnemonic() -> SecretText {
        SecretText::new(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                .to_owned(),
        )
    }

    #[test]
    fn generated_mnemonic_has_24_english_words() {
        let mnemonic = generate_mnemonic().expect("OS randomness should be available");
        let parsed = parse_mnemonic(&mnemonic).expect("generated mnemonic must parse");

        assert_eq!(parsed.word_count(), 24);
        assert_eq!(parsed.language(), Language::English);
    }

    #[test]
    fn derives_public_account_material() {
        let policy = DescriptorPolicy::bip84(Network::Regtest, 0);
        let derived = derive_public_keys(Network::Regtest, policy, &test_mnemonic(), None)
            .expect("valid BIP39/BIP32/BIP84 material");

        assert_eq!(derived.master_fingerprint.len(), 8);
        assert!(derived.account_xpub.starts_with("tpub"));
    }

    #[test]
    fn compares_mnemonic_and_xpub_addresses() {
        let policy = DescriptorPolicy::bip84(Network::Regtest, 0);
        let comparisons =
            compare_derived_addresses(Network::Regtest, policy, &test_mnemonic(), None, 3)
                .expect("derived addresses must match");

        assert_eq!(comparisons.len(), 6);
        assert!(comparisons.iter().all(AddressComparison::matches));
    }

    #[test]
    fn derived_public_descriptors_load_into_bdk() {
        let policy = DescriptorPolicy::bip84(Network::Regtest, 0);
        let mnemonic = test_mnemonic();
        let derived = derive_public_keys(Network::Regtest, policy, &mnemonic, None)
            .expect("valid BIP39/BIP32/BIP84 material");
        let descriptors =
            public_descriptors(policy, &derived.master_fingerprint, &derived.account_xpub)
                .expect("valid public descriptors");
        let wallet = Wallet::create(descriptors.external, descriptors.internal)
            .network(Network::Regtest)
            .create_wallet_no_persist()
            .expect("BDK should parse the recovered watch-only wallet");
        let address = wallet
            .peek_address(KeychainKind::External, 0)
            .address
            .to_string();
        let comparison = compare_derived_addresses(Network::Regtest, policy, &mnemonic, None, 1)
            .expect("derived addresses")
            .into_iter()
            .find(|comparison| comparison.keychain == Keychain::External)
            .expect("external address");

        assert_eq!(address, comparison.mnemonic_address);
    }
}
