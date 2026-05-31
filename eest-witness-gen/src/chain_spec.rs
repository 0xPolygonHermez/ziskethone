//! Map EEST fixture network strings ("Prague", "Osaka",
//! "CancunToPragueAtTime15k", …) into reth `ChainSpec` instances.
//!
//! Only Pectra+ forks are wired up (that's the cpp-guest target).
//! Transition specs ("…ToPragueAt…") build a chain spec with a
//! configurable hardfork timestamp/block.
//!
//! This is a thin wrapper over `reth_chainspec` builders; the
//! actual genesis and pre-state are seeded separately via
//! `reth_db_common::init::insert_genesis_state`.

use std::sync::Arc;

use anyhow::{bail, Result};
use reth_chainspec::{ChainSpec, ChainSpecBuilder, MAINNET};

/// Build a reth `ChainSpec` from an EEST `network` string.
///
/// The EEST format uses fork names directly (e.g. `Prague`) or
/// transition specs (`CancunToPragueAtTime15k`). For transition
/// specs the trailing number is the timestamp at which the fork
/// activates; on the basal fork side, all earlier forks are active
/// from genesis.
pub fn from_network(network: &str) -> Result<Arc<ChainSpec>> {
    // Mainnet baseline gives us all the genesis config + pre-Pectra
    // hardfork schedule. We then override the Pectra+ activation
    // timestamps based on the fork name.
    let base = ChainSpecBuilder::default()
        .chain(MAINNET.chain)
        .genesis(MAINNET.genesis.clone())
        .paris_activated();

    let spec = match network {
        "Cancun" => base.cancun_activated(),
        "Prague" => base.prague_activated(),
        "Osaka" => base.osaka_activated(),
        // Transition spec: "<FromFork>To<ToFork>AtTime<n>". The
        // pre-fork blocks must execute under the source fork; if we
        // activate the destination from genesis, block 0 picks up
        // Prague semantics (e.g. EIP-2935 system call) that the
        // fixture's header.state_root was generated WITHOUT, and
        // every downstream proof / hash mismatches. Parse the
        // trailing AtTime<n> timestamp and feed `with_prague_at` /
        // `with_osaka_at`.
        s if s.contains("ToPragueAt") => {
            let ts = parse_transition_timestamp(s, "ToPragueAtTime")?;
            base.cancun_activated().with_prague_at(ts)
        }
        s if s.contains("ToOsakaAt") => {
            let ts = parse_transition_timestamp(s, "ToOsakaAtTime")?;
            base.prague_activated().with_osaka_at(ts)
        }
        other => bail!(
            "unsupported EEST network '{}'; only Cancun/Prague/Osaka \
             (and ToPragueAt/ToOsakaAt transitions) wired up",
            other
        ),
    };

    Ok(Arc::new(spec.build()))
}

/// Parse an EEST transition-network string of the form
/// `<...><marker><digits>`, e.g. `CancunToPragueAtTime15000` with
/// `marker = "ToPragueAtTime"` → 15000. EEST may abbreviate the
/// number with a `k` suffix (`"15k"` = 15000) — we accept that too.
fn parse_transition_timestamp(s: &str, marker: &str) -> Result<u64> {
    let idx = s
        .find(marker)
        .ok_or_else(|| anyhow::anyhow!("network '{s}' missing marker '{marker}'"))?;
    let tail = &s[idx + marker.len()..];
    let (digits, suffix_mul) = match tail.strip_suffix('k') {
        Some(d) => (d, 1_000u64),
        None => (tail, 1u64),
    };
    let n: u64 = digits.parse().map_err(|e| {
        anyhow::anyhow!("network '{s}': bad timestamp '{digits}': {e}")
    })?;
    Ok(n.saturating_mul(suffix_mul))
}
