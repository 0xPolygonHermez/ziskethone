//! `reth-zisk`: a reth node that proves every block it receives by
//! newPayload with ZisK and submits the EIP-8025 execution proof to the
//! beacon node. See README.md.

mod beacon;
mod lighthouse;
mod pipeline;
mod precheck;
mod prover;
mod signer;
mod ssz;
mod tap;
mod witness;

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use futures::TryStreamExt;
use reth_ethereum::chainspec::EthChainSpec;
use reth_ethereum::cli::{chainspec::EthereumChainSpecParser, interface::Cli};
use reth_ethereum::exex::{ExExContext, ExExEvent, ExExNotification};
use reth_ethereum::node::api::FullNodeComponents;
use reth_ethereum::node::EthereumNode;
use tracing::info;

use crate::pipeline::{Config, Mode, Pipeline, Submitter};
use crate::precheck::Precheck;
use crate::prover::{CoordinatorProver, EmulatorProver, Prover};

#[derive(Debug, Clone, clap::Args)]
#[command(next_help_heading = "ZisK prover")]
struct ZiskArgs {
    /// What to do with each new block.
    #[arg(long = "zisk.mode", value_enum, default_value = "witness")]
    mode: Mode,
    /// Directory for per-block artifacts (input, proof, signed envelope, status).
    #[arg(long = "zisk.out-dir", default_value = "zisk-proofs")]
    out_dir: PathBuf,
    /// Native host build of the guest (only for --zisk.compare-exec).
    #[arg(long = "zisk.guest-host", default_value = "cpp-guest/build-sepolia/zisk_eth_guest", hide = true)]
    guest_host: PathBuf,
    /// Guest ELF (emulate and prove modes).
    #[arg(long = "zisk.elf")]
    elf: Option<PathBuf>,
    /// ziskemu binary (emulate mode).
    #[arg(long = "zisk.ziskemu", default_value = "ziskemu")]
    ziskemu: PathBuf,
    /// ZisK coordinator gRPC URL (prove mode).
    #[arg(long = "zisk.coordinator", default_value = "http://127.0.0.1:8000")]
    coordinator: String,
    /// Beacon node HTTP API (prove mode).
    #[arg(long = "zisk.beacon-url", default_value = "http://127.0.0.1:5052")]
    beacon_url: String,
    /// EIP-2335 keystore of the validator that signs the proofs.
    #[arg(long = "zisk.keystore", requires = "keystore_password_file")]
    keystore: Option<PathBuf>,
    /// File holding the keystore password.
    #[arg(long = "zisk.keystore-password-file")]
    keystore_password_file: Option<PathBuf>,
    /// Hex BLS secret key file (devnets), instead of a keystore.
    #[arg(long = "zisk.secret-key-file", conflicts_with = "keystore")]
    secret_key_file: Option<PathBuf>,
    /// Also take payloads straight from the beacon node (--zisk.beacon-url):
    /// its execution_payload_gossip events, then the envelope. A job starts
    /// on whichever of this and the engine's newPayload comes first.
    #[arg(long = "zisk.lighthouse-early", default_value_t = false)]
    lighthouse_early: bool,
    /// After each job, also build the re-execution input and compare it with
    /// the BAL-built one (measurement aid).
    #[arg(long = "zisk.compare-exec", default_value_t = false, hide = true)]
    compare_exec: bool,
    /// Build a BAL input only after reth has executed the block (warm trie
    /// pages) instead of at newPayload.
    #[arg(long = "zisk.after-execution", default_value_t = false, action = clap::ArgAction::Set)]
    after_execution: bool,
    /// POST signed proofs to the beacon node (otherwise only stored).
    #[arg(long = "zisk.submit", default_value_t = false)]
    submit: bool,
}

/// The ExEx itself: drain the canonical-chain notifications so reth can
/// prune behind them, and log reorgs. Proving is driven by the engine's
/// per-newPayload events (see `Pipeline`), not by these commits.
async fn exex<Node: FullNodeComponents>(mut ctx: ExExContext<Node>) -> eyre::Result<()> {
    while let Some(notification) = ctx.notifications.try_next().await? {
        match &notification {
            ExExNotification::ChainReorged { old, new } => {
                info!(from = ?old.range(), to = ?new.range(), "zisk exex: reorg");
            }
            ExExNotification::ChainReverted { old } => {
                info!(reverted = ?old.range(), "zisk exex: revert");
            }
            ExExNotification::ChainCommitted { .. } => {}
        }
        if let Some(chain) = notification.committed_chain() {
            ctx.events.send(ExExEvent::FinishedHeight(chain.tip().num_hash()))?;
        }
    }
    Ok(())
}

async fn build_config(args: &ZiskArgs, chain_id: u64) -> anyhow::Result<Config> {
    let elf = || args.elf.clone().context("--zisk.elf is required in this mode");
    let (prover, submitter) = match args.mode {
        Mode::Witness => (None, None),
        Mode::Emulate => {
            let p = EmulatorProver { ziskemu: args.ziskemu.clone(), elf: elf()?, work_dir: args.out_dir.join("emu") };
            (Some(Prover::Emulator(p)), None)
        }
        Mode::Prove => {
            let signer = match (&args.keystore, &args.keystore_password_file, &args.secret_key_file) {
                (Some(ks), Some(pw), _) => signer::Signer::from_keystore(ks, pw)?,
                (_, _, Some(sk)) => signer::Signer::from_secret_file(sk)?,
                _ => anyhow::bail!("prove mode needs --zisk.keystore or --zisk.secret-key-file"),
            };
            let beacon = beacon::BeaconClient::new(&args.beacon_url)?;
            let params = beacon.chain_params().await.context("reading the beacon chain spec")?;
            if params.deposit_chain_id != chain_id {
                anyhow::bail!(
                    "beacon node DEPOSIT_CHAIN_ID {} != execution chain id {chain_id}",
                    params.deposit_chain_id
                );
            }
            let validator_index = beacon.validator_index(&signer.pubkey()).await?;
            info!(validator_index, pubkey = %hex::encode(signer.pubkey()), proof_type = ssz::ZISK_PROOF_TYPE, "proof signer");
            let prover = CoordinatorProver::connect(&args.coordinator, &elf()?).await?;
            std::fs::create_dir_all(&args.out_dir)?;
            std::fs::write(args.out_dir.join("program_vk.hex"), format!("0x{}\n", hex::encode(&prover.program_vk)))?;
            let sub = Submitter { beacon, params, signer, validator_index, submit: args.submit };
            (Some(Prover::Coordinator(prover)), Some(sub))
        }
    };
    Ok(Config {
        mode: args.mode,
        chain_id,
        out_dir: args.out_dir.clone(),
        precheck: Precheck { guest_host: args.guest_host.clone() },
        prover,
        submitter,
        compare_exec: args.compare_exec,
        after_execution: args.after_execution,
    })
}

fn main() -> eyre::Result<()> {
    Cli::<EthereumChainSpecParser, ZiskArgs>::parse().run(async move |builder, args| {
        // Every newPayload is copied to the pipeline from the engine's
        // payload validator, before reth executes it.
        let (payload_tx, payload_rx) = tokio::sync::mpsc::channel(64);
        let payload_tx_lh = payload_tx.clone();
        // The engine tree builds its validator through the engine-validator
        // builder (the payload-validator slot is the engine RPC's).
        use reth_ethereum::node::builder::rpc::{
            BasicEngineApiBuilder, BasicEngineValidatorBuilder, Identity, RpcAddOns,
        };
        let add_ons = reth_ethereum::node::EthereumAddOns::new(RpcAddOns::new(
            <reth_ethereum::node::EthereumEthApiBuilder>::default(),
            reth_ethereum::node::EthereumEngineValidatorBuilder::default(),
            BasicEngineApiBuilder::<reth_ethereum::node::EthereumEngineValidatorBuilder>::default(),
            BasicEngineValidatorBuilder::new(tap::TapValidatorBuilder { tx: payload_tx }),
            Identity::new(),
            Identity::new(),
        ));
        let handle = builder
            .with_types::<EthereumNode>()
            .with_components(EthereumNode::components())
            .with_add_ons(add_ons)
            .install_exex("zisk", async move |ctx| Ok(exex(ctx)))
            .launch_with_debug_capabilities()
            .await?;
        let node = &handle.node;
        let chain_id = node.chain_spec().chain().id();
        // Fail fast on a chain with no compiled-in fork schedule.
        rust_input_gen::assemble::fork_params(chain_id, 0).map_err(|e| eyre::eyre!("{e}"))?;

        let cfg = build_config(&args, chain_id).await.map_err(|e| eyre::eyre!("{e:#}"))?;
        info!(mode = ?cfg.mode, out_dir = %cfg.out_dir.display(), "zisk prover pipeline started");
        if args.lighthouse_early {
            let (url, tx) = (args.beacon_url.trim_end_matches('/').to_string(), payload_tx_lh);
            node.task_executor.spawn_task(Box::pin(lighthouse::run(url, tx)));
        }
        let events = node.add_ons_handle.engine_events.new_listener();
        let pipeline = Pipeline::new(node.provider.clone(), node.evm_config.clone(), cfg);
        node.task_executor.spawn_critical_task("zisk prover pipeline", Box::pin(pipeline.run(events, payload_rx)));

        handle.wait_for_node_exit().await
    })
}
