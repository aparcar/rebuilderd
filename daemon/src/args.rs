use clap::{ArgAction, Parser};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(version)]
pub struct Args {
    /// Verbose logging
    #[arg(short, long, action(ArgAction::Count))]
    pub verbose: u8,
    /// Load and print a config
    #[arg(long, group = "action")]
    pub check_config: bool,
    /// Generate a signing keypair (this usually happens automatically)
    #[arg(long, group = "action")]
    pub keygen: bool,
    /// Derive the public key from a private key file
    #[arg(long, group = "action")]
    pub derive_pubkey: Option<PathBuf>,
    /// Configuration file path
    #[arg(short, long)]
    pub config: Option<PathBuf>,
    /// Long-term key used to sign attestations
    #[arg(
        long,
        env = "REBUILDERD_SIGNING_KEY",
        default_value = "./rebuilderd.sign.key"
    )]
    pub signing_key: PathBuf,
    /// Long-term post-quantum key used to counter-sign attestations
    #[cfg(feature = "pqc")]
    #[arg(
        long,
        env = "REBUILDERD_PQC_SIGNING_KEY",
        default_value = rebuilderd::config::DEFAULT_PQC_SIGNING_KEY
    )]
    pub pqc_signing_key: PathBuf,
    /// Operate on the post-quantum key instead, for --keygen and --derive-pubkey
    #[cfg(feature = "pqc")]
    #[arg(long)]
    pub pqc: bool,
}
