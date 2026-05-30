//! Execute an EEST fixture's blocks through reth, capturing each
//! block's `ExecutionWitness` along the way.
//!
//! Implementation pattern mirrors reth v2.2.0's
//! `crates/rpc/rpc/src/debug.rs::debug_execution_witness_for_block`
//! (the wire-level handler for `debug_executionWitness`) so the
//! witness shape we emit is byte-for-byte what reth would return
//! over JSON-RPC. The chain-state seeding + per-block commit loop
//! mirrors `testing/ef-tests/src/cases/blockchain_test.rs::run_case`.

use std::sync::Arc;

use alloy_consensus::BlockHeader as _;
use alloy_primitives::B256;
use alloy_rlp::Decodable;
use alloy_rpc_types_debug::ExecutionWitness;
use anyhow::{Context, Result};
use reth_chainspec::ChainSpec;
use reth_db_common::init::{
    insert_genesis_hashes, insert_genesis_history, insert_genesis_state,
};
use reth_ethereum_primitives::Block as RethBlock;
use reth_evm::{execute::Executor, ConfigureEvm};
use reth_evm_ethereum::EthEvmConfig;
use reth_primitives_traits::{RecoveredBlock, SealedBlock};
use reth_provider::{
    test_utils::create_test_provider_factory_with_chain_spec, BlockWriter,
    DatabaseProviderFactory, ExecutionOutcome, OriginalValuesKnown, StateWriteConfig,
    StateWriter, StaticFileProviderFactory, StaticFileSegment, StaticFileWriter,
};
use reth_revm::{database::StateProviderDatabase, witness::ExecutionWitnessRecord};
use reth_trie::ExecutionWitnessMode;
use revm::database::BundleState;

use crate::fixture::BlockchainTest;

/// One block's execution result, ready for the bridge to fold into
/// a `ManifestSources`.
pub struct ExecutedBlock {
    /// RLP-decoded reth block with senders recovered.
    pub block: RecoveredBlock<RethBlock>,
    /// Witness in the same shape `debug_executionWitness` returns.
    pub witness: ExecutionWitness,
    /// Block hash that reth's executor produced.
    pub computed_hash: B256,
    /// Post-execution `BundleState` — every account / storage slot
    /// that changed during the block, with both the original (pre-
    /// block) and present (post-block) values. The bridge uses this
    /// to derive the per-block prestate diff that rust-input-gen's
    /// online path normally pulls from `debug_traceBlockByHash`.
    pub bundle_state: BundleState,
}

/// Execute the full fixture and return one `ExecutedBlock` per
/// block. Errors abort the whole fixture (a downstream classifier
/// can split on `block.expect_exception` to distinguish positive
/// vs negative tests).
pub fn run_fixture(
    chain_spec: Arc<ChainSpec>,
    test: &BlockchainTest,
) -> Result<Vec<ExecutedBlock>> {
    // ---- (1) Fresh in-memory provider seeded with genesis ----
    let factory = create_test_provider_factory_with_chain_spec(chain_spec.clone());
    let provider = factory
        .database_provider_rw()
        .context("creating provider_rw")?;

    // Insert the test's genesis block. EEST gives us the header
    // verbatim; we wrap it as a sealed/recovered block with empty
    // body and push it as block 0 so subsequent blocks chain off
    // a real parent.
    let genesis_header_alloy: alloy_consensus::Header =
        eest_header_to_alloy(&test.genesis_block_header);
    let genesis_hash = test.genesis_block_header.hash;
    let genesis_sealed = SealedBlock::<RethBlock>::from_sealed_parts(
        reth_primitives_traits::SealedHeader::new(genesis_header_alloy, genesis_hash),
        Default::default(),
    )
    .try_recover()
    .map_err(|e| anyhow::anyhow!("recover genesis: {e:?}"))?;

    provider
        .insert_block(&genesis_sealed)
        .context("inserting genesis block")?;

    // Bump the receipts static file to align with block 0.
    provider
        .static_file_provider()
        .latest_writer(StaticFileSegment::Receipts)
        .and_then(|mut w| w.increment_block(0))
        .context("incrementing receipts static-file for genesis")?;

    // Seed the genesis account state.
    let genesis_state: std::collections::BTreeMap<_, _> = test
        .pre
        .iter()
        .map(|(addr, account)| {
            let storage: std::collections::BTreeMap<B256, B256> = account
                .storage
                .iter()
                .filter(|(_, v)| !v.is_zero())
                .map(|(k, v)| (B256::from(k.to_be_bytes()), B256::from(v.to_be_bytes())))
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

    insert_genesis_state(&provider, genesis_state.iter())
        .context("insert_genesis_state")?;
    insert_genesis_hashes(&provider, genesis_state.iter())
        .context("insert_genesis_hashes")?;
    insert_genesis_history(&provider, genesis_state.iter())
        .context("insert_genesis_history")?;

    let executor_provider = EthEvmConfig::ethereum(chain_spec.clone());
    let mut out = Vec::with_capacity(test.blocks.len());

    for (idx, fixture_block) in test.blocks.iter().enumerate() {
        let block_number = (idx + 1) as u64;

        // ---- (2) Decode + recover the block ----
        let decoded = SealedBlock::<RethBlock>::decode(&mut fixture_block.rlp.as_ref())
            .with_context(|| format!("RLP-decode block {idx}"))?;
        let recovered = decoded
            .try_recover()
            .map_err(|e| anyhow::anyhow!("recover block {idx}: {e:?}"))?;

        // Persist into the provider so subsequent blocks see it as
        // their parent (matches ef-tests).
        provider
            .insert_block(&recovered)
            .with_context(|| format!("insert_block {idx}"))?;
        provider
            .static_file_provider()
            .commit()
            .with_context(|| format!("static_file commit {idx}"))?;

        // ---- (3) Execute with witness closure ----
        let state_provider = provider.latest();
        let state_db = StateProviderDatabase(&state_provider);
        let mut state = reth_revm::db::State::builder()
            .with_database(state_db)
            .with_bundle_update()
            .build();

        let block_executor = executor_provider.executor(&mut state);
        let mut witness_record = ExecutionWitnessRecord::default();
        let mode = ExecutionWitnessMode::Canonical;
        let output = block_executor
            .execute_with_state_closure(&recovered, |statedb: &reth_revm::db::State<_>| {
                witness_record.record_executed_state(statedb, mode);
            })
            .with_context(|| format!("execute block {idx}"))?;

        // ---- (4) Materialize the witness in RPC shape ----
        let exec_witness = witness_record
            .into_execution_witness(&state.database.0, &provider, block_number, mode)
            .with_context(|| format!("into_execution_witness {idx}"))?;

        // ---- (5) Commit post-state to the provider for the next
        // block. We clone `output.state` first because both the
        // `ExecutionOutcome` (which `write_state` consumes) and our
        // returned `ExecutedBlock` need it.
        let bundle_state = output.state.clone();
        let outcome = ExecutionOutcome::single(recovered.header().number(), output);
        provider
            .write_state(&outcome, OriginalValuesKnown::Yes, StateWriteConfig::default())
            .with_context(|| format!("write_state {idx}"))?;

        let computed_hash = recovered.hash();
        out.push(ExecutedBlock {
            block: recovered,
            witness: exec_witness,
            computed_hash,
            bundle_state,
        });
    }

    Ok(out)
}

/// Convert the EEST `Header` model (numeric fields are `U256`-ish
/// JSON-friendly) into reth's `alloy_consensus::Header` (numeric
/// fields are `u64`). Mirror of the same conversion in reth's
/// `testing/ef-tests/src/models.rs::From<Header> for SealedHeader`.
fn eest_header_to_alloy(h: &crate::fixture::Header) -> alloy_consensus::Header {
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
