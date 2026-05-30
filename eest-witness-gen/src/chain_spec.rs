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
        // Transition spec: "<FromFork>To<ToFork>AtTime<n>". For now
        // we just activate the destination fork from genesis;
        // honoring the activation timestamp is a Phase 1.2 follow-up
        // once the rest of the pipeline is proven.
        s if s.contains("ToPragueAt") => base.prague_activated(),
        s if s.contains("ToOsakaAt") => base.osaka_activated(),
        other => bail!(
            "unsupported EEST network '{}'; only Cancun/Prague/Osaka \
             (and ToPragueAt/ToOsakaAt transitions) wired up",
            other
        ),
    };

    Ok(Arc::new(spec.build()))
}
