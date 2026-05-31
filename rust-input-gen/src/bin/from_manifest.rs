//! `input-gen-from-manifest` — second entry point that builds the
//! cpp-guest binary input from a pre-recorded JSON manifest instead
//! of a live JSON-RPC node.
//!
//! The manifest's schema is exactly `OfflineSources` serialized via
//! serde_json. Workflow:
//!
//! 1. Either the live `input-gen` binary or a future EEST-driven
//!    producer (`eest-witness-gen`) emits an `OfflineSources` JSON
//!    file.
//! 2. This binary loads it and pipes through the same pure
//!    `offline::build_binary` the live path uses.
//!
//! Because both paths funnel through `build_binary`, the same
//! manifest always produces a byte-identical input.bin — verified by
//! `tests/roundtrip.rs`. That guarantee is the foundation for the
//! eventual EEST conformance suite: if reth's witness on an EEST
//! fixture serializes into an `OfflineSources` that produces a
//! input.bin the cpp-guest accepts, we know the witness is complete.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::info;

use rust_input_gen::offline::{build_binary, OfflineSources};

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Build a cpp-guest binary input from a pre-recorded OfflineSources JSON manifest."
)]
struct Args {
    /// Path to the JSON manifest (an `OfflineSources` serialized via
    /// `serde_json`).
    #[arg(long)]
    manifest: PathBuf,

    /// Output binary path.
    #[arg(long, default_value = "build/block_input.bin")]
    output: PathBuf,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    info!(
        manifest = %args.manifest.display(),
        output = %args.output.display(),
        "loading manifest",
    );

    let json = std::fs::read_to_string(&args.manifest)
        .with_context(|| format!("reading manifest {}", args.manifest.display()))?;
    let sources: OfflineSources = serde_json::from_str(&json)
        .with_context(|| format!("parsing manifest {}", args.manifest.display()))?;
    info!(
        block_number = sources.current.header.number,
        block_hash = %sources.current.header.hash,
        accounts = sources.prestate.len(),
        ancestors = sources.ancestors.len(),
        "loaded OfflineSources",
    );

    build_binary(&sources, &args.output)
}
