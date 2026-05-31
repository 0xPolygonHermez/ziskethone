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
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
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
    DatabaseProviderFactory, ExecutionOutcome, HistoryWriter, OriginalValuesKnown,
    StateProofProvider, StateProviderFactory, StateWriteConfig, StateWriter,
    StaticFileProviderFactory, StaticFileSegment, StaticFileWriter, StorageSettingsCache,
    TrieWriter,
};
use reth_trie::{HashedPostState, KeccakKeyHasher, StateRoot};
use reth_trie_db::DatabaseStateRoot;
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
    /// Every (addr, slot) pair the EVM READ during execution — wider
    /// than `bundle_state.storage` which only contains slots that
    /// changed value. The bridge uses this to populate prestate
    /// storage so cpp-guest's Storages::index_of never fatals on a
    /// SLOAD of an untouched-but-read slot. Recovered by reverse-
    /// hashing `hashed_state.storages` via `keys` preimages.
    pub touched_slot_pairs: std::collections::BTreeSet<(Address, B256)>,
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

    // Populate trie tables from genesis state. ef-tests doesn't do
    // this explicitly — it relies on overlay_root cursors rebuilding
    // the trie from hashed tables. But the rebuild walks every leaf
    // on every query, which is slow for many-account fixtures AND
    // the resulting intermediate-node hashes don't necessarily match
    // the canonical genesis trie reth's writer produces. For
    // overlay_account_proof to return proofs rooted at the
    // fixture's genesis state root, we precompute the trie via the
    // same overlay primitive and persist its nodes.
    {
        let mut hps = HashedPostState::default();
        for (addr, gacc) in &genesis_state {
            let hashed_addr = keccak256::<&[u8]>(addr.as_slice());
            let bytecode_hash = gacc
                .code
                .as_ref()
                .filter(|c| !c.is_empty())
                .map(|c| keccak256::<&[u8]>(c.as_ref()));
            let info = reth_primitives_traits::Account {
                nonce: gacc.nonce.unwrap_or(0),
                balance: gacc.balance,
                bytecode_hash,
            };
            hps.accounts.insert(hashed_addr, Some(info));
            if let Some(storage_map) = &gacc.storage {
                let mut hs = reth_trie::HashedStorage::default();
                for (slot, val) in storage_map {
                    if val.is_zero() {
                        continue;
                    }
                    let hashed_slot = keccak256::<&[u8]>(slot.as_slice());
                    hs.storage.insert(hashed_slot, U256::from_be_bytes(val.0));
                }
                if !hs.storage.is_empty() {
                    hps.storages.insert(hashed_addr, hs);
                }
            }
        }
        let sorted = hps.into_sorted();
        let (_genesis_root, trie_updates) = reth_trie_db::with_adapter!(provider, |A| {
            StateRoot::<reth_trie_db::DatabaseTrieCursorFactory<_, A>, _>::overlay_root_with_updates(
                provider.tx_ref(),
                &sorted,
            )
        })
        .context("computing genesis state root")?;
        provider
            .write_trie_updates(trie_updates)
            .context("write_trie_updates for genesis")?;
    }

    let executor_provider = EthEvmConfig::ethereum(chain_spec.clone());
    let mut out = Vec::with_capacity(test.blocks.len());

    // Track the input state root for each iteration so we can
    // inject its trie root node into the witness (reth's recorder
    // omits the root because it assumes a stateful consumer).
    // Block 0's input state == genesis state root.
    let mut input_state_root: B256 = test.genesis_block_header.state_root;

    // Accumulate every block's HashedPostState. Passed as the
    // TrieInput overlay to `overlay_account_proof` so the proof
    // walks the full in-memory state (post-block-N-1) rather than
    // the sparsely-materialized DB trie tables.
    let mut cumulative_hps: HashedPostState = test
        .pre
        .iter()
        .map(|(addr, acc)| {
            let hashed_addr = keccak256::<&[u8]>(addr.as_slice());
            let info = reth_primitives_traits::Account {
                nonce: acc.nonce.try_into().unwrap_or(0),
                balance: acc.balance,
                bytecode_hash: if acc.code.is_empty() {
                    None
                } else {
                    Some(keccak256::<&[u8]>(acc.code.as_ref()))
                },
            };
            (hashed_addr, Some(info))
        })
        .collect::<alloy_primitives::map::B256Map<_>>()
        .into_iter()
        .fold(HashedPostState::default(), |mut h, (k, v)| {
            h.accounts.insert(k, v);
            h
        });

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
        // Also capture every address the EVM TOUCHED (loaded into
        // state.cache.accounts), even ones with `account.account ==
        // None` (= account doesn't exist in trie). reth's witness
        // recorder filters those out of `keys`, but cpp-guest still
        // calls Accounts::index_of on them (DELEGATECALL to empty,
        // EXTCODESIZE on never-touched EOA, etc.) and fatals if
        // missing.
        let mut all_cached_addrs: std::collections::BTreeSet<Address> =
            std::collections::BTreeSet::new();
        let mode = ExecutionWitnessMode::Canonical;
        let output = block_executor
            .execute_with_state_closure(&recovered, |statedb: &reth_revm::db::State<_>| {
                witness_record.record_executed_state(statedb, mode);
                for addr in statedb.cache.accounts.keys() {
                    all_cached_addrs.insert(*addr);
                }
            })
            .with_context(|| format!("execute block {idx}"))?;

        // Capture the addr→slot read-set BEFORE the witness record
        // is consumed by into_execution_witness. The bridge will use
        // this to populate prestate storage with EVERY slot the EVM
        // read (not just writes from BundleState), so cpp-guest's
        // SLOAD path always finds a registered entry.
        let touched_slot_pairs: std::collections::BTreeSet<(Address, B256)> = {
            // Build a reverse map: hash(20B addr) → addr,
            //                     hash(32B slot) → slot.
            let mut addr_by_hash: std::collections::HashMap<B256, Address> =
                std::collections::HashMap::new();
            let mut slot_by_hash: std::collections::HashMap<B256, B256> =
                std::collections::HashMap::new();
            for k in &witness_record.keys {
                if k.len() == 20 {
                    let a = Address::from_slice(k);
                    addr_by_hash.insert(keccak256::<&[u8]>(k.as_ref()), a);
                } else if k.len() == 32 {
                    let s = B256::from_slice(k);
                    slot_by_hash.insert(keccak256::<&[u8]>(k.as_ref()), s);
                }
            }
            let mut s = std::collections::BTreeSet::new();
            for (hashed_addr, hashed_storage) in &witness_record.hashed_state.storages {
                if let Some(addr) = addr_by_hash.get(hashed_addr) {
                    for hashed_slot in hashed_storage.storage.keys() {
                        if let Some(slot) = slot_by_hash.get(hashed_slot) {
                            s.insert((*addr, *slot));
                        }
                    }
                }
            }
            // ALSO add (addr, slot) pairs straight from BundleState.
            // For accounts destroyed during the block, the recorder's
            // hashed_state.storages drops their slots (`account.account`
            // is None → outer iteration skips the inner storage loop),
            // but BundleAccount.storage retains every touched slot
            // regardless of final account status. EIP-7702 tests that
            // SSTORE then RESET delegation on an EOA, or that
            // SELFDESTRUCT a delegation target in the same tx, fall
            // here.
            for (addr, bundle_acc) in &output.state.state {
                for slot_u256 in bundle_acc.storage.keys() {
                    let slot = B256::from(slot_u256.to_be_bytes::<32>());
                    s.insert((*addr, slot));
                }
            }
            s
        };

        // ---- (4) Materialize the witness in RPC shape ----
        let mut exec_witness = witness_record
            .into_execution_witness(&state.database.0, &provider, block_number, mode)
            .with_context(|| format!("into_execution_witness {idx}"))?;

        // ---- (4') Inject the INPUT (parent) state-root node ----
        //
        // reth's witness only contains nodes that the EVM
        // materially traversed FROM the root downward — the root
        // node itself is omitted because reth's own state DB has
        // it cached. cpp-guest's verifier is purely stateless and
        // needs the root as the explicit entry point of every
        // trie walk. We synthesize it via a no-op account proof:
        // the first entry of any AccountProof IS the trie root
        // node. `input_state_root` is the post-block-(N-1) state
        // root (or genesis state root for block 0).
        // Merge nodes from a comprehensive multiproof for every
        // touched address+slot. reth's into_execution_witness only
        // emits nodes for state mutations; cpp-guest's verifier
        // walks the parent trie for every account in the prestate,
        // so we explicitly proof every address (and its touched
        // slots) at the INPUT state and merge.
        let mut already: std::collections::HashSet<B256> = exec_witness
            .state
            .iter()
            .map(|n| keccak256(n.as_ref()))
            .collect();

        // Append addresses the EVM cached but which never had
        // `account.account == Some(...)` (= touched-but-empty: a
        // DELEGATECALL target with no code, EXTCODESIZE on a never-
        // touched EOA, etc.) onto exec_witness.keys. Reth's witness
        // recorder omits these. Both cpp-guest's Accounts::index_of
        // and the bridge's `touched` derivation need them present.
        let existing_addrs: std::collections::HashSet<Address> = exec_witness
            .keys
            .iter()
            .filter(|k| k.len() == 20)
            .map(|k| Address::from_slice(k))
            .collect();
        for addr in &all_cached_addrs {
            if !existing_addrs.contains(addr) {
                exec_witness.keys.push(Bytes::from(addr.as_slice().to_vec()));
            }
        }
        // Similarly, append every storage slot from BundleState (the
        // write set) onto keys. The recorder iterates `account.storage`
        // only when `account.account.is_some()`, so an EIP-7702
        // pointer-reset that ends with the account as None drops its
        // slots. We rebuild the slot-preimage list from output.state
        // which retains them regardless of final account state.
        let existing_slots: std::collections::HashSet<B256> = exec_witness
            .keys
            .iter()
            .filter(|k| k.len() == 32)
            .map(|k| B256::from_slice(k))
            .collect();
        for (_addr, bundle_acc) in &output.state.state {
            for slot_u256 in bundle_acc.storage.keys() {
                let slot = B256::from(slot_u256.to_be_bytes::<32>());
                if !existing_slots.contains(&slot) {
                    exec_witness.keys.push(Bytes::from(slot.as_slice().to_vec()));
                }
            }
        }
        let mut touched_addrs: std::collections::BTreeSet<Address> = exec_witness
            .keys
            .iter()
            .filter(|k| k.len() == 20)
            .map(|k| Address::from_slice(k))
            .collect();
        // Also generate proofs for all Prague-era precompile
        // addresses 0x01..0x12. The bridge unconditionally seeds
        // these into the cpp-guest prestate (so its Accounts table
        // has them when the EVM CALLs a precompile), so the
        // verifier walks the parent trie for each. Without proofs,
        // the walk hits missing trie nodes. Cheap: most precompiles
        // are empty-account leaves (1-2 nodes from root).
        for i in 1u8..=0x12 {
            let mut bytes = [0u8; 20];
            bytes[19] = i;
            touched_addrs.insert(Address::from_slice(&bytes));
        }
        // Block coinbase + withdrawal recipients: same reason as
        // for precompiles — the bridge unconditionally adds these to
        // prestate, so the verifier walks them and needs proofs.
        // When the EVM never touched them (zero-tip blocks,
        // zero-amount withdrawals), reth's witness omits them.
        touched_addrs.insert(recovered.header().beneficiary());
        if let Some(wds) = recovered.body().withdrawals.as_ref() {
            for wd in wds.iter() {
                touched_addrs.insert(wd.address);
            }
        }
        let touched_slots: Vec<B256> = exec_witness
            .keys
            .iter()
            .filter(|k| k.len() == 32)
            .map(|k| B256::from_slice(k))
            .collect();

        // Build a MultiProofTargets map: each touched address ->
        // every touched slot (we don't know which slot belongs to
        // which contract, so we ask for all-by-all; reth handles
        // non-existent (addr, slot) pairs by returning sibling
        // nodes, which are also useful).
        use alloy_primitives::map::B256Set;
        use reth_trie::MultiProofTargets;
        let mut targets = MultiProofTargets::default();
        let hashed_slots: B256Set = touched_slots
            .iter()
            .map(|s| keccak256::<&[u8]>(s.as_slice()))
            .collect();
        for addr in &touched_addrs {
            targets.insert(keccak256::<&[u8]>(addr.as_slice()), hashed_slots.clone());
        }

        // Reth's multiproof at Default::default() returned 0 new
        // account nodes — it seems to assume the consumer has the
        // input trie root cached. We instead call state_provider
        // .witness(input=full_hashed_target, target=full_hashed_target,
        // mode=Canonical), which is the same call into_execution_witness
        // uses but with EVERY touched (addr, slot) as a target — that
        // forces every path from root to be materialized.
        //
        // For each touched address, look up its account info in the
        // pre-block state and build a HashedPostState with a "no-op"
        // entry (same values) so the witness function traces the path
        // but doesn't propose any change.
        use reth_trie::{HashedStorage, TrieInput};
        let mut hps = HashedPostState::default();
        for addr in &touched_addrs {
            let hashed_addr = keccak256::<&[u8]>(addr.as_slice());
            // Insert as `None` (= "no change to account info") so
            // the witness traces the existing path without proposing
            // any modification.
            hps.accounts.insert(hashed_addr, None);
            let mut hs = HashedStorage::default();
            for slot in &touched_slots {
                hs.storage.insert(keccak256::<&[u8]>(slot.as_slice()), U256::ZERO);
            }
            hps.storages.insert(hashed_addr, hs);
        }
        let trie_input = TrieInput::from_state(hps.clone());
        match state.database.0.witness(trie_input, hps, mode) {
            Ok(nodes) => {
                let mut added = 0;
                for node in nodes {
                    let h = keccak256(node.as_ref());
                    if already.insert(h) {
                        exec_witness.state.push(Bytes::from(node.to_vec()));
                        added += 1;
                    }
                }
                tracing::info!(
                    idx,
                    targets = targets.len(),
                    witness_added = added,
                    total_state_nodes = exec_witness.state.len(),
                    "state_provider.witness injection",
                );
            }
            Err(e) => {
                tracing::warn!(idx, "state_provider.witness failed: {e:#}");
            }
        }

        // ALSO per-address proof. Reth's MultiProof / state_provider.witness
        // omit the leaf nodes for unchanged accounts; AccountProof from the
        // singular `proof()` API includes them. (Trace: parent_root ->
        // intermediate branches -> last-level branch -> LEAF -> account RLP
        // with storage_root. The verifier needs the leaf to read storage_root.)
        // Build proofs against the in-memory HashedPostState using
        // reth's `DatabaseProof::overlay_account_proof`. This is
        // the same primitive reth uses internally for stateless
        // witness generation: it layers an `InMemoryTrieCursorFactory`
        // and `HashedPostStateCursorFactory` over the DB cursors so
        // the cursor walks see the FULL (overlay + DB) trie. Plain
        // `state_provider.proof()` only walks the DB trie tables —
        // which our test provider barely populates — and returned
        // shallow proofs (depth=2) for addresses on a 5-deep trie.
        use reth_trie_db::DatabaseProof;
        // Build per-address proofs using reth's with_adapter macro
        // so the DatabaseTrieCursorFactory's `A` table-adapter type
        // is selected automatically. Empty TrieInput: the DB already
        // has the post-block-(N-1) trie via prior write_trie_updates
        // calls, so walking it directly yields proofs rooted at
        // recovered.parent_hash() — exactly what cpp-guest needs.
        // Earlier we passed `cumulative_hps` as overlay; this
        // double-counted genesis accounts already in the DB and
        // produced proofs at a different root.
        let trie_input = TrieInput::default();
        for addr in &touched_addrs {
            let result = reth_trie_db::with_adapter!(provider, |A| {
                let proof_builder = reth_trie::proof::Proof::<
                    reth_trie_db::DatabaseTrieCursorFactory<_, A>,
                    reth_trie_db::DatabaseHashedCursorFactory<_>,
                >::from_tx(provider.tx_ref());
                proof_builder.overlay_account_proof(
                    trie_input.clone(),
                    *addr,
                    &touched_slots,
                )
            });
            match result {
                Ok(p) => {
                    for node in p.proof.iter() {
                        let h = keccak256(node.as_ref());
                        if already.insert(h) {
                            exec_witness.state.push(Bytes::from(node.to_vec()));
                        }
                    }
                    for sp in &p.storage_proofs {
                        for node in &sp.proof {
                            let h = keccak256(node.as_ref());
                            if already.insert(h) {
                                exec_witness.state.push(Bytes::from(node.to_vec()));
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(idx, %addr, "overlay_account_proof failed: {e:#}");
                }
            }
        }

        // ALSO call multiproof with a TrieInput::from_state(target_hps)
        // — different from witness() because multiproof returns the
        // proof PATH for each target, including unchanged intermediate
        // nodes from the input state. state_provider.witness only
        // returns nodes for the actual change set.
        let mut target_hps = HashedPostState::default();
        for addr in &touched_addrs {
            let ha = keccak256::<&[u8]>(addr.as_slice());
            target_hps.accounts.insert(ha, None);
        }
        let mp_input = TrieInput::from_state(target_hps);
        match state.database.0.multiproof(mp_input, targets.clone()) {
            Ok(mp) => {
                let mut a = 0;
                let mut s = 0;
                for (_path, node) in mp.account_subtree.into_inner() {
                    let h = keccak256(node.as_ref());
                    if already.insert(h) {
                        exec_witness.state.push(Bytes::from(node.to_vec()));
                        a += 1;
                    }
                }
                for (_addr, subtree) in mp.storages {
                    for (_path, node) in subtree.subtree.into_inner() {
                        let h = keccak256(node.as_ref());
                        if already.insert(h) {
                            exec_witness.state.push(Bytes::from(node.to_vec()));
                            s += 1;
                        }
                    }
                }
                tracing::info!(
                    idx,
                    mp2_account = a,
                    mp2_storage = s,
                    "multiproof v2 injection",
                );
            }
            Err(e) => {
                tracing::warn!(idx, "multiproof v2 failed: {e:#}");
            }
        }

        // ---- (5) Commit post-state to the provider for the next
        // block. Three writes mirror ef-tests' run_case: write the
        // bundle into plain state tables, write the hashed state
        // into the trie tables (so subsequent `proof()` queries see
        // the new state), and update history indices.
        let bundle_state = output.state.clone();
        let hashed_state =
            HashedPostState::from_bundle_state::<KeccakKeyHasher>(bundle_state.state());
        let outcome = ExecutionOutcome::single(recovered.header().number(), output);
        provider
            .write_state(&outcome, OriginalValuesKnown::Yes, StateWriteConfig::default())
            .with_context(|| format!("write_state {idx}"))?;
        // Compute the post-block state root WITH trie updates. The
        // updates contain every modified trie node, which we then
        // write to the trie tables so subsequent proof()/multiproof()
        // queries on the same provider see the post-block trie state
        // (not the pre-block snapshot).
        let sorted_hps = hashed_state.clone_into_sorted();
        let (_root, trie_updates) = reth_trie_db::with_adapter!(provider, |A| {
            StateRoot::<reth_trie_db::DatabaseTrieCursorFactory<_, A>, _>::overlay_root_with_updates(
                provider.tx_ref(),
                &sorted_hps,
            )
        })
        .with_context(|| format!("overlay_root_with_updates {idx}"))?;
        provider
            .write_hashed_state(&hashed_state.clone().into_sorted())
            .with_context(|| format!("write_hashed_state {idx}"))?;
        provider
            .write_trie_updates(trie_updates)
            .with_context(|| format!("write_trie_updates {idx}"))?;
        provider
            .update_history_indices(
                recovered.header().number()..=recovered.header().number(),
            )
            .with_context(|| format!("update_history_indices {idx}"))?;

        // Advance input_state_root for the next iteration: block
        // N+1's input state == block N's post-execution state.
        input_state_root = recovered.header().state_root();

        // Fold this block's hashed state changes into the
        // cumulative overlay used by the next block's
        // overlay_account_proof calls.
        cumulative_hps.extend(hashed_state.clone());

        let computed_hash = recovered.hash();
        out.push(ExecutedBlock {
            block: recovered,
            witness: exec_witness,
            computed_hash,
            bundle_state,
            touched_slot_pairs,
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
