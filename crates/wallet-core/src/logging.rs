use std::fmt;

/// Wrapper that prevents sensitive values from appearing in Debug or Display.
pub struct Redacted<T>(pub T);

impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl<T> fmt::Display for Redacted<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

pub const LOG_POLICY_VERSION: u16 = 1;

pub const FORBIDDEN_LOG_FIELDS: &[&str] = &[
    "mnemonic",
    "bip39_passphrase",
    "xprv",
    "tprv",
    "private_key",
    "gpg_passphrase",
    "rpc_password",
    "psbt_secret",
];
