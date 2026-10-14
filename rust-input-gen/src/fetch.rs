//! Live-RPC fetching: all logic to build an `OfflineSources` bundle
//! from a JSON-RPC endpoint. Extracted from `main.rs` so the library
//! can expose in-process entry points without spawning the CLI.

use alloy::primitives::B256;
use anyhow::Result;
use tracing::info;

use crate::offline::OfflineSources;
use crate::rpc;

/// Live-RPC adapter: fetch everything `OfflineSources` needs from
/// the node: the block, then its execution witness, the same two
/// calls reth's input makes. Ancestors come solely
/// from `witness.headers` — no RPC ancestor walk. Returns a fully
/// resolved bundle that `offline::build_binary` can encode without
/// further network access.
pub(crate) async fn fetch_offline_sources_online(
    client: &rpc::Client,
    block: u64,
    // Retained for API/CLI compatibility. Ancestors now come solely from
    // `witness.headers` (the guest resolves BLOCKHASH by number over a
    // sparse set), so there is no RPC ancestor walk left to depth-bound.
    _ancestors_depth: u64,
) -> Result<OfflineSources> {
    // ---- (1) Discover the canonical anchor hash ----
    //
    // The parent is then recovered from the witness by `parent_hash`.
    // Nothing rechecks the anchor after the witness call; see
    // `rpc::Client::execution_witness` for why a reorg in between is
    // tolerated.
    let current = client.block_by_number_full(block).await?;
    let block_hash: B256 = current.header.hash;
    let parent_hash: B256 = current.header.parent_hash;
    info!(
        %block_hash,
        %parent_hash,
        "anchored block hash",
    );

    // Witness first (a non-archive node prunes trie state within a few blocks
    // of head, so grab it before anything else). Sequential — no concurrency.
    let witness = client
        .execution_witness(current.header.number, block_hash)
        .await?;
    info!(
        state_nodes = witness.state.len(),
        codes = witness.codes.len(),
        keys = witness.keys.len(),
        headers = witness.headers.len(),
        "fetched execution witness",
    );

    // Every account and slot the block accesses must become a leaf in the
    // StateRoot section (an empty one if it doesn't exist), so the guest can
    // halt on anything else. reth's `witness.keys` lists each account that
    // exists after the block followed by its slots, but drops accessed
    // accounts that never existed; the prestate tracer lists every account
    // and slot the transactions touch, including those. The witness already
    // carries their absence proofs. `sources_from_parts` adds the witness
    // keys, the beneficiary and the withdrawal recipients.
    let mut accessed = crate::state_root::Accessed::new();
    for (addr, acc) in client.prestate_by_hash(block_hash).await? {
        accessed.entry(addr).or_default().extend(acc.storage.keys().copied());
    }

    // Fork schedule is compiled in per chain (see `assemble::fork_params`);
    // the node's chain id selects it.
    let chain_id = client.chain_id().await?;

    let sources = crate::assemble::sources_from_parts(chain_id, current, witness, accessed)?;
    info!(
        accounts = sources.accessed.len(),
        slots = sources.accessed.values().map(|s| s.len()).sum::<usize>(),
        "collected accessed keys",
    );
    Ok(sources)
}
