#![forbid(unsafe_code)]
//! Interface-free wallet core for Frostlock Wallet.
//!
//! This crate deliberately knows nothing about the terminal, GUI, GPG, or
//! filesystem. Those responsibilities belong to adapter layers.

pub use bdk_wallet::bitcoin::Network;

pub mod descriptors;
pub mod errors;
pub mod keys;
pub mod logging;
pub mod policy;
pub mod secret_format;
