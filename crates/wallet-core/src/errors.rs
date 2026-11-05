use std::fmt;

/// Stable codes for the CLI and future GUI.
///
/// Error messages must never include secrets, mnemonics, xprvs, passwords,
/// PSBT contents, or RPC credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    InvalidInput,
    InvalidNetwork,
    InvalidFingerprint,
    InvalidPublicKey,
    InvalidSecretFormat,
    SecretInPublicDescriptor,
    UnsupportedOperation,
    ChainBackend,
    Persistence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletError {
    code: ErrorCode,
    message: &'static str,
}

impl WalletError {
    pub const fn new(code: ErrorCode, message: &'static str) -> Self {
        Self { code, message }
    }

    pub const fn code(&self) -> ErrorCode {
        self.code
    }
}

impl fmt::Display for WalletError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for WalletError {}

impl ErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::InvalidNetwork => "invalid_network",
            Self::InvalidFingerprint => "invalid_fingerprint",
            Self::InvalidPublicKey => "invalid_public_key",
            Self::InvalidSecretFormat => "invalid_secret_format",
            Self::SecretInPublicDescriptor => "secret_in_public_descriptor",
            Self::UnsupportedOperation => "unsupported_operation",
            Self::ChainBackend => "chain_backend",
            Self::Persistence => "persistence",
        }
    }
}

pub type Result<T> = std::result::Result<T, WalletError>;
