use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::info;

mod binary;
mod rpc;

use binary::{BinaryWriter, SectionKind};
use rpc::RpcClient;

/// Fetch an Ethereum block (header, txs, witness) via JSON-RPC and write a
/// binary input file consumable by the ZisK C++ guest program.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// JSON-RPC endpoint URL (must expose `debug_executionWitness` for full
    /// stateless execution input).
    #[arg(long, env = "ETH_RPC_URL", default_value = "http://localhost:8545")]
    rpc_url: String,

    /// Block number to verify.
    #[arg(long)]
    block: u64,

    /// Output binary path.
    #[arg(long, default_value = "build/block_input.bin")]
    output: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    info!(block = args.block, rpc = %args.rpc_url, "fetching block bundle");

    let client = RpcClient::new(&args.rpc_url);
    let bundle = client.fetch_block_bundle(args.block).await?;

    let mut w = BinaryWriter::new(bundle.chain_id, bundle.block_number);
    w.push(SectionKind::ParentHeader, bundle.parent_header_rlp);
    w.push(SectionKind::CurrentHeader, bundle.current_header_rlp);
    w.push(
        SectionKind::Transactions,
        BinaryWriter::encode_blob_list(&bundle.transactions_rlp)?,
    );
    w.push(
        SectionKind::Withdrawals,
        BinaryWriter::encode_blob_list(&bundle.withdrawals_rlp)?,
    );
    w.push(
        SectionKind::AncestorHeaders,
        BinaryWriter::encode_blob_list(&bundle.ancestor_headers_rlp)?,
    );
    w.push(
        SectionKind::StateTrieNodes,
        BinaryWriter::encode_blob_list(&bundle.state_trie_nodes)?,
    );
    w.push(
        SectionKind::StorageTrieNodes,
        BinaryWriter::encode_blob_list(&bundle.storage_trie_nodes)?,
    );
    w.push(
        SectionKind::Bytecodes,
        BinaryWriter::encode_blob_list(&bundle.bytecodes)?,
    );

    let bytes = w.finish()?;
    if let Some(parent) = args.output.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating output dir {}", parent.display()))?;
    }
    std::fs::write(&args.output, &bytes)
        .with_context(|| format!("writing {}", args.output.display()))?;

    info!(path = %args.output.display(), bytes = bytes.len(), "wrote input file");
    Ok(())
}
