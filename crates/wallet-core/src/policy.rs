use serde::{Deserialize, Serialize};

use crate::{Network, errors::Result};

/// Derivation policy for the first wallet version.
///
/// The policy is serializable because it is part of the recovery contract. It
/// contains no private material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DescriptorPolicy {
    pub purpose: u32,
    pub coin_type: u32,
    pub account: u32,
}

impl DescriptorPolicy {
    pub const BIP84_PURPOSE: u32 = 84;

    pub fn bip84(network: Network, account: u32) -> Self {
        Self {
            purpose: Self::BIP84_PURPOSE,
            coin_type: if network == Network::Bitcoin { 0 } else { 1 },
            account,
        }
    }

    pub fn external_path(self) -> String {
        format!(
            "m/{}'/{}'/{}'/0/*",
            self.purpose, self.coin_type, self.account
        )
    }

    pub fn internal_path(self) -> String {
        format!(
            "m/{}'/{}'/{}'/1/*",
            self.purpose, self.coin_type, self.account
        )
    }

    pub fn validate(self) -> Result<()> {
        if self.purpose != Self::BIP84_PURPOSE {
            return Err(crate::errors::WalletError::new(
                crate::errors::ErrorCode::InvalidInput,
                "only BIP84 is supported by this version",
            ));
        }

        if self.coin_type > 1 {
            return Err(crate::errors::WalletError::new(
                crate::errors::ErrorCode::InvalidInput,
                "unsupported coin type",
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bip84_uses_mainnet_coin_type_zero() {
        let policy = DescriptorPolicy::bip84(Network::Bitcoin, 0);

        assert_eq!(policy.external_path(), "m/84'/0'/0'/0/*");
        assert_eq!(policy.internal_path(), "m/84'/0'/0'/1/*");
    }

    #[test]
    fn bip84_uses_test_coin_type_one() {
        let policy = DescriptorPolicy::bip84(Network::Regtest, 0);

        assert_eq!(policy.external_path(), "m/84'/1'/0'/0/*");
        assert_eq!(policy.internal_path(), "m/84'/1'/0'/1/*");
    }
}
