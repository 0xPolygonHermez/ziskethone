//! Reference execution tracer for one block of an EEST fixture.
//!
//! Replays the fixture through reth's real block executor up to (and
//! including) the target block, attaching revm's built-in EIP-3155
//! struct-log inspector (`TracerEip3155`) for that block. Unlike the
//! cpp-guest `ZEG_TRACE_OPCODES` tracer (which only has access to
//! evmone's *static* per-opcode gas table), this tracer's `gasCost`
//! field is the real per-instruction cost, computed by revm's own
//! `GasInspector` from before/after gas-remaining — the ground truth
//! this tool exists to provide.
//!
//! Output is one JSON object per instruction, written to `--output` as
//! JSONL, with `TX <idx> START` / `TX <idx> gas_used=<n>` marker lines
//! bracketing every transaction in the block (same convention as the
//! cpp-guest tracer) so a script can slice out one tx's trace to diff
//! directly against the guest's own `ZEG_TRACE_OPCODES` output.
//!
//! Usage:
//! ```text
//! eest-trace --fixture <path> --test <substring> --block <idx> --output <path>
//! ```
//! `--test` must match exactly one test name in the fixture (the file
//! contains one test per fork/parametrization); `--block` is the
//! 0-indexed position in that test's `blocks` array.

#[path = "../fixture.rs"]
mod fixture;
#[path = "../chain_spec.rs"]
mod chain_spec;

use std::io::Write;
use std::path::PathBuf;

use alloy_consensus::BlockHeader as _;
use alloy_rlp::Decodable;
use anyhow::{bail, Context, Result};
use clap::Parser;
use reth_db_common::init::{insert_genesis_hashes, insert_genesis_history, insert_genesis_state};
use reth_ethereum_primitives::Block as RethBlock;
use reth_evm::{
    execute::{BlockExecutor, Executor},
    ConfigureEvm,
};
use reth_evm_ethereum::EthEvmConfig;
use reth_primitives_traits::SealedBlock;
use reth_provider::{
    test_utils::create_test_provider_factory_with_chain_spec, BlockWriter,
    DatabaseProviderFactory, ExecutionOutcome, OriginalValuesKnown, StateWriteConfig,
    StateWriter, StaticFileProviderFactory, StaticFileSegment, StaticFileWriter,
};
use reth_revm::database::StateProviderDatabase;
use revm::inspector::inspectors::TracerEip3155;

use fixture::load_fixture;

#[derive(Debug, Parser)]
#[command(about = "Trace one block of an EEST fixture through reth's real executor (EIP-3155 struct logs).")]
struct Args {
    /// Path to a single EEST blockchain-test JSON file.
    #[arg(long)]
    fixture: PathBuf,
    /// Substring match against the fixture's test names; must match exactly one.
    #[arg(long)]
    test: String,
    /// 0-indexed block within the matched test's `blocks` array to trace.
    #[arg(long)]
    block: usize,
    /// Where to write the JSONL trace.
    #[arg(long, default_value = "build/eest-trace.jsonl")]
    output: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let fixture = load_fixture(&args.fixture)
        .with_context(|| format!("loading fixture {}", args.fixture.display()))?;

    let matches: Vec<&String> = fixture.keys().filter(|k| k.contains(&args.test)).collect();
    let name = match matches.as_slice() {
        [one] => (*one).clone(),
        [] => bail!("no test name contains {:?} (fixture has {} tests)", args.test, fixture.len()),
        many => bail!(
            "ambiguous --test {:?}: {} matches:\n{}",
            args.test,
            many.len(),
            many.iter().map(|s| format!("  {s}")).collect::<Vec<_>>().join("\n")
        ),
    };
    let test = &fixture[&name];
    if args.block >= test.blocks.len() {
        bail!("--block {} out of range: test {:?} has {} blocks", args.block, name, test.blocks.len());
    }
    eprintln!(
        "tracing test={name:?} network={} block={}/{}",
        test.network,
        args.block,
        test.blocks.len()
    );

    let chain_spec = chain_spec::from_network(&test.network)?;

    // ---- genesis seeding: mirrors executor.rs::run_fixture's setup,
    // minus the witness/proof machinery this tool doesn't need (we only
    // care about correct execution, not producing a stateless witness).
    let factory = create_test_provider_factory_with_chain_spec(chain_spec.clone());
    let provider = factory.database_provider_rw().context("creating provider_rw")?;

    let genesis_header_alloy = eest_header_to_alloy(&test.genesis_block_header);
    let genesis_sealed = SealedBlock::<RethBlock>::from_sealed_parts(
        reth_primitives_traits::SealedHeader::new(
            genesis_header_alloy,
            test.genesis_block_header.hash,
        ),
        Default::default(),
    )
    .try_recover()
    .map_err(|e| anyhow::anyhow!("recover genesis: {e:?}"))?;
    provider.insert_block(&genesis_sealed).context("inserting genesis block")?;
    provider
        .static_file_provider()
        .latest_writer(StaticFileSegment::Receipts)
        .and_then(|mut w| w.increment_block(0))
        .context("incrementing receipts static-file for genesis")?;

    let genesis_state: std::collections::BTreeMap<_, _> = test
        .pre
        .iter()
        .map(|(addr, account)| {
            let storage: std::collections::BTreeMap<_, _> = account
                .storage
                .iter()
                .filter(|(_, v)| !v.is_zero())
                .map(|(k, v)| {
                    (
                        alloy_primitives::B256::from(k.to_be_bytes()),
                        alloy_primitives::B256::from(v.to_be_bytes()),
                    )
                })
                .collect();
            let g = alloy_genesis::GenesisAccount {
                balance: account.balance,
                nonce: Some(account.nonce.try_into().unwrap_or(0)),
                code: Some(account.code.clone()).filter(|c| !c.is_empty()),
                storage: Some(storage),
                private_key: None,
            };
            (*addr, g)
        })
        .collect();
    insert_genesis_state(&provider, genesis_state.iter()).context("insert_genesis_state")?;
    insert_genesis_hashes(&provider, genesis_state.iter()).context("insert_genesis_hashes")?;
    insert_genesis_history(&provider, genesis_state.iter()).context("insert_genesis_history")?;

    let executor_provider = EthEvmConfig::ethereum(chain_spec.clone());

    let out_file = std::fs::File::create(&args.output)
        .with_context(|| format!("creating {}", args.output.display()))?;

    for (idx, fixture_block) in test.blocks.iter().enumerate() {
        let decoded = SealedBlock::<RethBlock>::decode(&mut fixture_block.rlp.as_ref())
            .with_context(|| format!("RLP-decode block {idx}"))?;
        let recovered = decoded
            .try_recover()
            .map_err(|e| anyhow::anyhow!("recover block {idx}: {e:?}"))?;

        provider.insert_block(&recovered).with_context(|| format!("insert_block {idx}"))?;
        provider
            .static_file_provider()
            .commit()
            .with_context(|| format!("static_file commit {idx}"))?;

        let state_provider = provider.latest();
        let state_db = StateProviderDatabase(&state_provider);
        let mut state = reth_revm::db::State::builder()
            .with_database(state_db)
            .with_bundle_update()
            .build();

        if idx < args.block {
            // Replay untraced: fast path, no inspector, just need
            // correct post-state for the next iteration.
            let executor = executor_provider.executor(&mut state);
            let output = executor
                .execute(&recovered)
                .with_context(|| format!("execute block {idx}"))?;
            let outcome = ExecutionOutcome::single(recovered.header().number(), output);
            provider
                .write_state(&outcome, OriginalValuesKnown::Yes, StateWriteConfig::default())
                .with_context(|| format!("write_state {idx}"))?;
            continue;
        }

        // ---- target block: attach the EIP-3155 tracer for the whole
        // block (system calls + every tx), bracketing each tx with our
        // own markers so a script can slice out exactly one tx's trace.
        let evm_env = executor_provider
            .evm_env(recovered.header())
            .map_err(|e| anyhow::anyhow!("evm_env: {e}"))?;
        let tracer = TracerEip3155::new(Box::new(
            out_file.try_clone().context("cloning output file handle")?,
        ));
        let evm = executor_provider.evm_with_env_and_inspector(&mut state, evm_env, tracer);
        let ctx = executor_provider
            .context_for_block(recovered.sealed_block())
            .map_err(|e| anyhow::anyhow!("context_for_block: {e}"))?;
        let mut block_executor = executor_provider.create_executor(evm, ctx);
        block_executor
            .apply_pre_execution_changes()
            .context("apply_pre_execution_changes")?;

        let mut marker = out_file.try_clone().context("cloning output file handle")?;
        for (tx_idx, tx) in recovered.transactions_recovered().enumerate() {
            writeln!(marker, "TX {tx_idx} START")?;
            let gas_output = block_executor
                .execute_transaction(tx)
                .with_context(|| format!("execute_transaction block {idx} tx {tx_idx}"))?;
            writeln!(marker, "TX {tx_idx} gas_used={}", gas_output.tx_gas_used())?;
        }
        block_executor.finish().context("finish block executor")?;
        marker.flush().ok();

        eprintln!("trace written to {}", args.output.display());
        return Ok(());
    }

    unreachable!("--block index checked against test.blocks.len() above");
}

/// Mirror of `executor.rs::eest_header_to_alloy` — duplicated here
/// since `src/bin/*.rs` binaries can't reach `main.rs`'s private
/// modules directly.
fn eest_header_to_alloy(h: &fixture::Header) -> alloy_consensus::Header {
    alloy_consensus::Header {
        parent_hash: h.parent_hash,
        ommers_hash: h.uncle_hash,
        beneficiary: h.coinbase,
        state_root: h.state_root,
        transactions_root: h.transactions_trie,
        receipts_root: h.receipt_trie,
        logs_bloom: h.bloom,
        difficulty: h.difficulty,
        number: h.number.to::<u64>(),
        gas_limit: h.gas_limit.to::<u64>(),
        gas_used: h.gas_used.to::<u64>(),
        timestamp: h.timestamp.to::<u64>(),
        mix_hash: h.mix_hash,
        nonce: alloy_primitives::B64::from(u64::from_be_bytes(h.nonce.0).to_be_bytes()),
        base_fee_per_gas: h.base_fee_per_gas.map(|v| v.to::<u64>()),
        withdrawals_root: h.withdrawals_root,
        blob_gas_used: h.blob_gas_used.map(|v| v.to::<u64>()),
        excess_blob_gas: h.excess_blob_gas.map(|v| v.to::<u64>()),
        parent_beacon_block_root: h.parent_beacon_block_root,
        requests_hash: h.requests_hash,
        extra_data: h.extra_data.clone(),
        block_access_list_hash: None,
        slot_number: None,
    }
}
