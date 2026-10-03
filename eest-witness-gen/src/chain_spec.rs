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
use std::collections::BTreeMap;

use alloy_eips::eip7840::BlobParams;
use alloy_eips::eip7892::BlobScheduleBlobParams;
use reth_chainspec::{ChainSpec, ChainSpecBuilder, EthereumHardfork, ForkCondition, MAINNET};

use crate::fixture::BlobScheduleEntry;

/// Build a reth `ChainSpec` from an EEST `network` string.
///
/// The EEST format uses fork names directly (e.g. `Prague`) or
/// transition specs (`CancunToPragueAtTime15k`). For transition
/// specs the trailing number is the timestamp at which the fork
/// activates; on the basal fork side, all earlier forks are active
/// from genesis.
///
/// `blob_schedule` is the fixture's `config.blobSchedule`, used for the
/// BPO forks' blob parameters.
pub fn from_network(
    network: &str,
    blob_schedule: &BTreeMap<String, BlobScheduleEntry>,
) -> Result<Arc<ChainSpec>> {
    // Mainnet baseline gives us the genesis config + chain id. Each
    // arm activates the requested fork (which also activates all
    // earlier ones), so block 0 of a `Berlin`-pinned fixture sees
    // exactly Berlin rules — not a later fork's gas schedule.
    let new_base = || {
        ChainSpecBuilder::default()
            .chain(MAINNET.chain)
            .genesis(MAINNET.genesis.clone())
    };

    // BPO transition: "<Osaka|BPOn>ToBPOm<AtTime…>". BPO forks keep the
    // Osaka rules and only change the blob parameters, which come from
    // the fixture (BPO3/BPO4 use test-only values). ChainSpecBuilder
    // drops any blob schedule, so set the scheduled params directly.
    if let Some((from, rest)) = network.split_once("ToBPO") {
        let ts = parse_transition_timestamp(network, "AtTime")?;
        let to = format!("BPO{}", rest.split("AtTime").next().unwrap());
        let params = |fork: &str| -> Result<BlobParams> {
            let e = blob_schedule
                .get(fork)
                .ok_or_else(|| anyhow::anyhow!("network '{network}': no blobSchedule for {fork}"))?;
            Ok(BlobParams {
                target_blob_count: e.target.to(),
                max_blob_count: e.max.to(),
                update_fraction: e.base_fee_update_fraction.to(),
                ..BlobParams::osaka()
            })
        };
        let mut scheduled = Vec::new();
        if from.starts_with("BPO") {
            scheduled.push((0, params(from)?));
        }
        scheduled.push((ts, params(&to)?));
        let mut spec = new_base().osaka_activated().build();
        spec.blob_params = BlobScheduleBlobParams::default().with_scheduled(scheduled);
        return Ok(Arc::new(spec));
    }

    let spec = match network {
        // Pre-Paris forks (EEST Osaka EIP-7883 modexp-gas backward-
        // compat tests pin to these).
        "Berlin"   => new_base().berlin_activated(),
        "London"   => new_base().london_activated(),
        "Paris"    => new_base().paris_activated(),
        "Shanghai" => new_base().shanghai_activated(),
        // Pectra+ forks (the original Prague target set).
        "Cancun"   => new_base().cancun_activated(),
        "Prague"   => new_base().prague_activated(),
        "Osaka"    => new_base().osaka_activated(),
        // Transition spec: "<FromFork>To<ToFork>AtTime<n>". The
        // pre-fork blocks must execute under the source fork; if we
        // activate the destination from genesis, block 0 picks up
        // post-transition semantics (e.g. EIP-2935 system call) that
        // the fixture's header.state_root was generated WITHOUT, and
        // every downstream proof / hash mismatches. Parse the
        // trailing AtTime<n> timestamp and activate the destination
        // fork there.
        s if s.contains("ToShanghaiAt") => {
            let ts = parse_transition_timestamp(s, "ToShanghaiAtTime")?;
            new_base()
                .paris_activated()
                .with_fork(EthereumHardfork::Shanghai, ForkCondition::Timestamp(ts))
        }
        s if s.contains("ToCancunAt") => {
            let ts = parse_transition_timestamp(s, "ToCancunAtTime")?;
            new_base()
                .shanghai_activated()
                .with_fork(EthereumHardfork::Cancun, ForkCondition::Timestamp(ts))
        }
        s if s.contains("ToPragueAt") => {
            let ts = parse_transition_timestamp(s, "ToPragueAtTime")?;
            new_base().cancun_activated().with_prague_at(ts)
        }
        s if s.contains("ToOsakaAt") => {
            let ts = parse_transition_timestamp(s, "ToOsakaAtTime")?;
            new_base().prague_activated().with_osaka_at(ts)
        }
        other => bail!(
            "unsupported EEST network '{}'; only Berlin/London/Paris/\
             Shanghai/Cancun/Prague/Osaka (and To{{Shanghai,Cancun,Prague,\
             Osaka,BPOn}}At transitions) wired up",
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
