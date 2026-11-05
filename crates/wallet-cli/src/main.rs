use std::path::PathBuf;

use bitcoincore_rpc::{Auth, Client, RpcApi};
use clap::{Parser, Subcommand, ValueEnum};
use frostlock_wallet_core::{
    Network,
    descriptors::public_descriptors,
    keys::{compare_derived_addresses, derive_public_keys, generate_mnemonic},
    policy::DescriptorPolicy,
    secret_format::WalletSecretV1,
};
use frostlock_wallet_secret_store_gpg::GpgSecretStore;

const APP_NAME: &str = "Frostlock Wallet";

#[derive(Debug, Parser)]
#[command(
    name = "frostlock-wallet",
    version,
    about = "Local text-mode Bitcoin wallet"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Display the BIP84 policy for a network.
    Policy { network: NetworkArg },

    /// Build public descriptors from a fingerprint and xpub.
    Descriptor {
        network: NetworkArg,
        #[arg(long)]
        fingerprint: String,
        #[arg(long)]
        xpub: String,
    },

    /// Generate a 24-word wallet and create an encrypted GPG backup.
    Create {
        network: NetworkArg,
        #[arg(long)]
        recipient: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 0)]
        account: u32,
        #[arg(long)]
        gpg_home: Option<PathBuf>,
    },

    /// Restore an encrypted GPG backup and display public recovery data.
    Restore {
        backup: PathBuf,
        #[arg(long)]
        gpg_home: Option<PathBuf>,
    },

    /// Compare mnemonic-derived and xpub-derived BIP84 addresses.
    CompareAddresses {
        backup: PathBuf,
        #[arg(long, default_value_t = 5)]
        count: u32,
        #[arg(long)]
        gpg_home: Option<PathBuf>,
    },

    /// Verify that RPC is connected to a Bitcoin Core regtest node.
    RegtestCheck {
        #[arg(long, default_value = "http://127.0.0.1:18443")]
        rpc_url: String,
        #[arg(long)]
        cookie: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum NetworkArg {
    Bitcoin,
    Testnet,
    Testnet4,
    Signet,
    Regtest,
}

impl NetworkArg {
    const fn network(self) -> Network {
        match self {
            Self::Bitcoin => Network::Bitcoin,
            Self::Testnet => Network::Testnet,
            Self::Testnet4 => Network::Testnet4,
            Self::Signet => Network::Signet,
            Self::Regtest => Network::Regtest,
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::Policy { network } => {
            let policy = DescriptorPolicy::bip84(network.network(), 0);
            println!("application: {APP_NAME}");
            println!("network: {:?}", network.network());
            println!("purpose: {}", policy.purpose);
            println!("coin_type: {}", policy.coin_type);
            println!("external: {}", policy.external_path());
            println!("internal: {}", policy.internal_path());
        }
        Command::Descriptor {
            network,
            fingerprint,
            xpub,
        } => {
            let policy = DescriptorPolicy::bip84(network.network(), 0);
            let descriptors = public_descriptors(policy, &fingerprint, &xpub)?;
            println!("external: {}", descriptors.external);
            println!("internal: {}", descriptors.internal);
            println!("note: checksum and cryptographic parsing will be performed by BDK");
        }
        Command::Create {
            network,
            recipient,
            output,
            account,
            gpg_home,
        } => {
            let network = network.network();
            let policy = DescriptorPolicy::bip84(network, account);
            let mnemonic = generate_mnemonic()?;
            let secret = WalletSecretV1::new(
                network_name(network).to_owned(),
                policy,
                recipient.clone(),
                mnemonic.expose().to_owned(),
            );
            let derived = derive_public_keys(network, policy, &secret.mnemonic, None)?;
            let first_address =
                compare_derived_addresses(network, policy, &secret.mnemonic, None, 1)?
                    .into_iter()
                    .find(|comparison| {
                        comparison.keychain
                            == frostlock_wallet_core::descriptors::Keychain::External
                    })
                    .expect("external address comparison");

            let store = GpgSecretStore::new(gpg_home)?;
            store.backup_to(&secret, &recipient, &output)?;
            print_recovery_summary(&derived);
            println!("backup: {}", output.display());
            println!("first_receive_address: {}", first_address.mnemonic_address);
            println!("mnemonic: withheld; recover it from the encrypted GPG backup");
        }
        Command::Restore { backup, gpg_home } => {
            let store = GpgSecretStore::new(gpg_home)?;
            let secret = store.restore_from(&backup)?;
            let network = parse_network(&secret.network)?;
            let derived = derive_public_keys(
                network,
                secret.policy,
                &secret.mnemonic,
                secret.bip39_passphrase.as_ref(),
            )?;
            print_recovery_summary(&derived);
            println!("backup: {}", backup.display());
            println!("recovery: valid");
        }
        Command::CompareAddresses {
            backup,
            count,
            gpg_home,
        } => {
            let store = GpgSecretStore::new(gpg_home)?;
            let secret = store.restore_from(&backup)?;
            let network = parse_network(&secret.network)?;
            let comparisons = compare_derived_addresses(
                network,
                secret.policy,
                &secret.mnemonic,
                secret.bip39_passphrase.as_ref(),
                count,
            )?;

            println!("address_comparison: ok");
            for comparison in comparisons {
                println!(
                    "keychain: {:?} index: {} mnemonic_address: {} xpub_address: {} match: {}",
                    comparison.keychain,
                    comparison.index,
                    comparison.mnemonic_address,
                    comparison.xpub_address,
                    comparison.matches(),
                );
            }
        }
        Command::RegtestCheck { rpc_url, cookie } => {
            let rpc = Client::new(&rpc_url, Auth::CookieFile(cookie))?;
            let info = rpc.get_blockchain_info()?;

            if info.chain != Network::Regtest {
                return Err(
                    format!("RPC is connected to {:?}, expected regtest", info.chain).into(),
                );
            }

            println!("regtest: ok");
            println!("blocks: {}", info.blocks);
            println!("best_block: {}", info.best_block_hash);
        }
    }

    Ok(())
}

fn print_recovery_summary(derived: &frostlock_wallet_core::keys::DerivedPublicKeys) {
    println!("application: {APP_NAME}");
    println!("network: {:?}", derived.network);
    println!("purpose: {}", derived.policy.purpose);
    println!("coin_type: {}", derived.policy.coin_type);
    println!("account: {}", derived.policy.account);
    println!("master_fingerprint: {}", derived.master_fingerprint);
    println!("account_xpub: {}", derived.account_xpub);
    if let Ok(descriptors) = public_descriptors(
        derived.policy,
        &derived.master_fingerprint,
        &derived.account_xpub,
    ) {
        println!("external_descriptor: {}", descriptors.external);
        println!("internal_descriptor: {}", descriptors.internal);
    }
}

fn parse_network(value: &str) -> Result<Network, Box<dyn std::error::Error>> {
    match value {
        "bitcoin" => Ok(Network::Bitcoin),
        "testnet" => Ok(Network::Testnet),
        "testnet4" => Ok(Network::Testnet4),
        "signet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        _ => Err(format!("unsupported wallet network: {value}").into()),
    }
}

fn network_name(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => "bitcoin",
        Network::Testnet => "testnet",
        Network::Testnet4 => "testnet4",
        Network::Signet => "signet",
        Network::Regtest => "regtest",
    }
}
