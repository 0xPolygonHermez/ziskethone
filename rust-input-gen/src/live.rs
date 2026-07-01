//! In-process live-RPC entry points, so external consumers (e.g.
//! zisk-eth-client's host) can fetch a block bundle and encode the
//! cpp-guest binary without spawning the `input-gen` CLI. Both wrap the
//! same `fetch_offline_sources_online` + `offline::build_binary` the CLI
//! uses, so output is byte-identical to the binary's.

use alloy::rpc::types::BlockTransactions;
use anyhow::Result;

use crate::offline::{self, OfflineSources};
use crate::rpc;

/// Fetch one block's stateless-re-execution bundle over JSON-RPC.
pub async fn fetch_offline_sources(
    rpc_url: &str,
    block: u64,
    ancestors: u64,
) -> Result<OfflineSources> {
    if block == 0 {
        anyhow::bail!("block 0 has no parent; pick a later block");
    }
    let client = rpc::Client::new(rpc_url)?;
    crate::fetch_offline_sources_online(&client, block, ancestors).await
}

/// Stats surfaced alongside the encoded input, for host-side filenames/logging.
pub struct InputStats {
    pub chain_id: u64,
    pub block_number: u64,
    pub tx_count: usize,
    pub gas_used: u64,
}

/// Like `fetch_and_build_bytes` but also returns block stats pulled from the
/// fetched `OfflineSources` + the node's chain id.
pub async fn fetch_and_build_with_stats(
    rpc_url: &str,
    block: u64,
    ancestors: u64,
) -> Result<(Vec<u8>, InputStats)> {
    if block == 0 {
        anyhow::bail!("block 0 has no parent; pick a later block");
    }
    let client = rpc::Client::new(rpc_url)?;
    let chain_id = client.chain_id().await?;
    let sources = crate::fetch_offline_sources_online(&client, block, ancestors).await?;
    let stats = InputStats {
        chain_id,
        block_number: sources.current.header.number,
        tx_count: match &sources.current.transactions {
            BlockTransactions::Full(v) => v.len(),
            BlockTransactions::Hashes(v) => v.len(),
            BlockTransactions::Uncle => 0,
        },
        gas_used: sources.current.header.gas_used,
    };
    let bytes = offline::encode_binary(&sources)?;
    Ok((bytes, stats))
}

/// Fetch + encode in one call, returning the `ZEG0` binary as bytes
/// (no file written). This is what the host's ZiskethoneClient consumes.
pub async fn fetch_and_build_bytes(rpc_url: &str, block: u64, ancestors: u64) -> Result<Vec<u8>> {
    let sources = fetch_offline_sources(rpc_url, block, ancestors).await?;
    offline::encode_binary(&sources)
}

#[cfg(test)]
mod tests {
    //! Compile-only contract guard. Nothing in this crate calls the host-facing
    //! entry points (their consumer, zisk-eth-client, lives in another repo), so
    //! `cargo build` alone wouldn't catch a signature drift or a `pub` -> private
    //! change. This test forces every host symbol to type-check at its documented
    //! signature; the bodies never run (`if false`), so no network is touched.
    use super::*;

    #[test]
    fn host_entry_points_typecheck() {
        if false {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let _: OfflineSources =
                rt.block_on(async { fetch_offline_sources("", 1, 0).await.unwrap() });
            let _: Vec<u8> = rt.block_on(async { fetch_and_build_bytes("", 1, 0).await.unwrap() });
            let _: (Vec<u8>, InputStats) =
                rt.block_on(async { fetch_and_build_with_stats("", 1, 0).await.unwrap() });
        }
    }
}
