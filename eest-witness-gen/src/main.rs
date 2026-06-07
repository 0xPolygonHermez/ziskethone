//! `eest-witness-gen` — load an EEST blockchain-test fixture and
//! emit a manifest that `input-gen-from-manifest` can consume to
//! build a cpp-guest binary input.
//!
//! ## Pipeline
//!
//! ```
//! EEST JSON fixture
//!    └─→ eest-witness-gen (this binary)
//!           ├─→ [Phase 1.0: implemented] parse + summarize the fixture
//!           ├─→ [Phase 1.1: TODO] execute via reth, capture
//!           │                     ExecutionWitnessRecord
//!           └─→ [Phase 1.2: TODO] emit OfflineSources JSON per block
//!                                 to disk
//!    └─→ input-gen-from-manifest (existing)
//!           └─→ block_input.bin
//!    └─→ zisk_eth_guest (existing)
//!           └─→ block hash (compare against fixture.lastblockhash)
//! ```
//!
//! ## Current (Phase 1.0)
//!
//! Scaffolding only: parses the EEST JSON, dumps a per-test summary
//! to stdout, and exits. Confirms the fixture format is readable and
//! gives us a clean entry point to layer reth on top in the next
//! work block.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::info;

mod bridge;
mod chain_spec;
mod executor;
mod fixture;
mod manifest;

use fixture::load_fixture;

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Load an EEST blockchain-test fixture (scaffold; full pipeline pending Phase 1.1+)."
)]
struct Args {
    /// Path to a single EEST blockchain-test JSON file.
    #[arg(long)]
    fixture: PathBuf,

    /// Optional output directory. When the reth integration lands,
    /// per-block OfflineSources manifests are written here as
    /// `<test_name>/block-<idx>.json`.
    #[arg(long, default_value = "build/eest-manifests")]
    output_dir: PathBuf,
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
        fixture = %args.fixture.display(),
        output_dir = %args.output_dir.display(),
        "loading EEST fixture",
    );

    let fixture = load_fixture(&args.fixture)
        .with_context(|| format!("loading fixture {}", args.fixture.display()))?;

    info!(test_count = fixture.len(), "parsed fixture");

    // Phase 1.0: dump a per-test summary so we can verify the parser
    // handles the corpus before layering reth on top.
    for (name, test) in &fixture {
        println!("== {name}");
        println!("   network:         {}", test.network);
        println!(
            "   genesis state:   {} accounts ({} with storage)",
            test.pre.len(),
            test.pre.values().filter(|a| !a.storage.is_empty()).count(),
        );
        println!("   genesis hash:    {}", test.genesis_block_header.hash);
        println!("   blocks:          {}", test.blocks.len());
        for (i, b) in test.blocks.iter().enumerate() {
            let (hash, num) = b
                .block_header
                .as_ref()
                .map(|h| (h.hash.to_string(), h.number.to_string()))
                .unwrap_or_else(|| ("<no header>".into(), "?".into()));
            let exc = b
                .expect_exception
                .as_deref()
                .map(|e| format!(" expect-exception=\"{e}\""))
                .unwrap_or_default();
            println!(
                "   block[{i}]:      #{num} {hash} rlp={}B{exc}",
                b.rlp.len()
            );
        }
        println!("   lastblockhash:   {}", test.lastblockhash);
        if let Some(post) = &test.post_state {
            println!("   post_state:      {} accounts", post.len());
        }
        println!();
    }

    // Phase 1.2: execute → bridge → write per-block manifest JSON.
    // Each `<output_dir>/<test_slug>/block-<i>.json` is a fully-
    // resolved `OfflineSources` payload that rust-input-gen's
    // `input-gen-from-manifest` binary can consume.
    std::fs::create_dir_all(&args.output_dir)
        .with_context(|| format!("creating {}", args.output_dir.display()))?;

    let mut total_blocks = 0usize;
    let mut hash_matches = 0usize;
    let mut written = 0usize;

    for (name, test) in &fixture {
        info!(test = %name, network = %test.network, blocks = test.blocks.len(), "executing");

        let chain_spec = match chain_spec::from_network(&test.network) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(test = %name, "skipping: {e}");
                continue;
            }
        };

        let executed = match executor::run_fixture(chain_spec.clone(), test) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(test = %name, "execution failed: {e:#}");
                continue;
            }
        };

        for (i, b) in executed.iter().enumerate() {
            total_blocks += 1;
            let expected = test
                .blocks
                .get(i)
                .and_then(|fb| fb.block_header.as_ref())
                .map(|h| h.hash);
            if expected.map(|e| e == b.computed_hash).unwrap_or(false) {
                hash_matches += 1;
            }
        }

        let manifests = match bridge::manifests_for_fixture(&chain_spec, test, &executed) {
            Ok(m) => m,
            Err(e) => {
                tracing::error!(test = %name, "bridge failed: {e:#}");
                continue;
            }
        };

        let mut slug = name
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect::<String>();
        // Cap the directory-name component well under the OS filename limit
        // (255 bytes on macOS/ext4). EEST parametrized test names can exceed it,
        // which would fail `create_dir_all` with "File name too long". Keep a
        // readable prefix and append a deterministic hash of the full name for
        // uniqueness.
        if slug.len() > 200 {
            use std::hash::{Hash, Hasher};
            let mut h = std::collections::hash_map::DefaultHasher::new();
            name.hash(&mut h);
            slug.truncate(180);
            slug.push_str(&format!("_{:016x}", h.finish()));
        }
        let test_dir = args.output_dir.join(&slug);
        std::fs::create_dir_all(&test_dir)
            .with_context(|| format!("creating {}", test_dir.display()))?;

        for (i, m) in manifests.iter().enumerate() {
            let path = test_dir.join(format!("block-{i}.json"));
            let json = serde_json::to_string(m)
                .with_context(|| format!("serializing manifest {}", path.display()))?;
            std::fs::write(&path, &json)
                .with_context(|| format!("writing {}", path.display()))?;
            // Write a sidecar `block-{i}.expect` containing the EEST
            // fixture's expect_exception string (or empty if the block
            // is a positive test). Downstream classifiers (the sweep
            // script) read this to treat correctly-failing negative
            // tests as expected outcomes, not bugs.
            let expect_path = test_dir.join(format!("block-{i}.expect"));
            let expect_str = test
                .blocks
                .get(i)
                .and_then(|b| b.expect_exception.as_deref())
                .unwrap_or("");
            std::fs::write(&expect_path, expect_str)
                .with_context(|| format!("writing {}", expect_path.display()))?;
            written += 1;
        }

        info!(
            test = %name,
            blocks = executed.len(),
            manifests_written = manifests.len(),
            "fixture done",
        );
    }

    info!(
        total_blocks,
        hash_matches,
        manifests_written = written,
        "summary",
    );
    Ok(())
}
