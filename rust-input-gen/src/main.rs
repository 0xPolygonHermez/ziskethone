//! `input-gen` — fetch one Ethereum block's stateless-re-execution
//! inputs from a JSON-RPC endpoint and write a binary file the ZisK
//! C++ guest (`zisk_eth_guest`) consumes. See `BINARY_FORMAT.md`.
//!
//! Phase 4: every input-stream section is real (ConsensusInfo,
//! Transactions, Accounts, Contracts, Storages, PreviousBlocks).
//! StateRoot trie-hint stream remains a single `Op::Empty` placeholder
//! until Phase 5.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::info;

use rust_input_gen::errors::ReorgDetected;
use rust_input_gen::offline::build_binary;

/// sysexits.h `EX_TEMPFAIL` — returned to the OS when we detect that
/// the upstream node reorged during our run. `scripts/verify_blocks.py`
/// recognizes this code and re-queues the block instead of recording
/// a failure. Any other error keeps the existing non-zero exit (1).
const EXIT_CODE_REORG: i32 = 75;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// JSON-RPC endpoint URL. The node must support the standard
    /// `eth_*` namespace; later phases also need `debug_*`.
    #[arg(long, env = "ETH_RPC_URL", default_value = "http://localhost:8545")]
    rpc_url: String,

    /// Block number to fetch.
    #[arg(long)]
    block: u64,

    /// Number of ancestor blocks to include in the PreviousBlocks
    /// section. Index 0 = parent (always included — the cpp-guest
    /// derives parent's block hash from this entry for BLOCKHASH and
    /// for the reconstructed header). Index 1 = grandparent, ....
    /// The EVM BLOCKHASH opcode reaches back 256, so the default is
    /// 256 (the spec-maximum) — any value lower risks an in-block
    /// BLOCKHASH(N) returning zeros and diverging execution.
    #[arg(long, default_value_t = 256)]
    ancestors: u64,

    /// Output binary path.
    #[arg(long, default_value = "build/block_input.bin")]
    output: PathBuf,

    /// Optionally dump the fully-resolved `OfflineSources` bundle
    /// (everything the encoder reads) to a JSON manifest at this
    /// path. Replaying the same manifest through `input-gen-from-
    /// manifest` produces a byte-identical input.bin — useful for
    /// recording mainnet fixtures for the EEST-style offline test
    /// pipeline, and for diagnosing reproducibility issues without
    /// keeping a live RPC reachable.
    #[arg(long)]
    dump_manifest: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    if let Err(err) = run(args).await {
        // Distinguish reorg-class errors (transient, retryable) from
        // every other failure so `scripts/verify_blocks.py` can
        // auto-retry without recording a failure artifact.
        if let Some(reorg) = err.downcast_ref::<ReorgDetected>() {
            eprintln!("Error: {reorg}");
            std::process::exit(EXIT_CODE_REORG);
        }
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}

async fn run(args: Args) -> Result<()> {
    info!(
        block = args.block,
        rpc = %args.rpc_url,
        output = %args.output.display(),
        ancestors = args.ancestors,
        "fetching block bundle",
    );

    if args.block == 0 {
        anyhow::bail!("block 0 has no parent; pick a later block");
    }

    let sources =
        rust_input_gen::live::fetch_offline_sources(&args.rpc_url, args.block, args.ancestors)
            .await?;

    if let Some(manifest_path) = &args.dump_manifest {
        if let Some(parent_dir) = manifest_path.parent() {
            std::fs::create_dir_all(parent_dir)
                .with_context(|| format!("creating manifest dir {}", parent_dir.display()))?;
        }
        let json = serde_json::to_string(&sources).context("serializing OfflineSources")?;
        std::fs::write(manifest_path, &json)
            .with_context(|| format!("writing manifest {}", manifest_path.display()))?;
        info!(
            path = %manifest_path.display(),
            bytes = json.len(),
            "wrote OfflineSources manifest",
        );
    }

    build_binary(&sources, &args.output)
}
