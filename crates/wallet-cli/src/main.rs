use std::path::PathBuf;

use bitcoincore_rpc::{Auth, Client, RpcApi};
use clap::{Parser, Subcommand, ValueEnum};
use frostlock_wallet_core::{Network, descriptors::public_descriptors, policy::DescriptorPolicy};

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
    Signet,
    Regtest,
}

impl NetworkArg {
    const fn network(self) -> Network {
        match self {
            Self::Bitcoin => Network::Bitcoin,
            Self::Testnet => Network::Testnet,
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
