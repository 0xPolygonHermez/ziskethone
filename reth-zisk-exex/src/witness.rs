//! The ZEG0 guest input of a block, built in-process from the node's state:
//! the same execution witness `debug_executionWitness` returns, plus every
//! account and slot the block accesses (which `input-gen` gets from the
//! prestate tracer), handed to `rust_input_gen::assemble`.

use std::sync::{Arc, Mutex};

use alloy_consensus::{BlockHeader as _, TxEnvelope};
use alloy_eips::eip2718::{Decodable2718, Encodable2718};
use alloy_primitives::{Address, B256, KECCAK256_EMPTY};
use anyhow::{Context, Result};
use reth_ethereum::evm::primitives::{execute::Executor, ConfigureEvm};
use revm::database::OnStateHook;
use reth_ethereum::evm::revm::database::StateProviderDatabase;
use reth_ethereum::evm::revm::witness::ExecutionWitnessRecord;
use reth_ethereum::primitives::{RecoveredBlock, SealedBlock};
use reth_ethereum::provider::{HeaderProvider, StateProviderFactory};
use reth_ethereum::storage::EvmStateProviderAdapter;
use reth_ethereum::{Block, EthPrimitives};
use reth_trie_common::ExecutionWitnessMode;
use revm::bytecode::Bytecode;
use revm::state::AccountInfo;
use revm::Database;
use rust_input_gen::offline::OfflineSources;
use rust_input_gen::state_root::Accessed;
use tracing::debug;

type Keys = Arc<Mutex<Accessed>>;

/// `OnStateHook` that records every account and slot of each tx's state
/// changes. That still holds the slots of an account created and
/// self-destructed in the same tx, which the `State` cache drops.
#[derive(Clone, Default)]
struct KeyRecorder(Keys);

impl OnStateHook for KeyRecorder {
    fn on_state(&mut self, state: revm::state::EvmState) {
        let mut keys = self.0.lock().unwrap();
        for (addr, account) in &state {
            keys.entry(*addr)
                .or_default()
                .extend(account.storage.keys().map(|k| B256::from(k.to_be_bytes::<32>())));
        }
    }
}

/// A `Database` that records every account and slot read from the parent
/// state, including slots of accounts the block later destroys.
struct RecordingDb<DB> {
    inner: DB,
    keys: Keys,
}

impl<DB> std::fmt::Debug for RecordingDb<DB> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecordingDb")
    }
}

impl<DB: Database> Database for RecordingDb<DB> {
    type Error = DB::Error;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.keys.lock().unwrap().entry(address).or_default();
        self.inner.basic(address)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.inner.code_by_hash(code_hash)
    }

    fn storage(
        &mut self,
        address: Address,
        index: alloy_primitives::U256,
    ) -> Result<alloy_primitives::U256, Self::Error> {
        self.keys
            .lock()
            .unwrap()
            .entry(address)
            .or_default()
            .insert(B256::from(index.to_be_bytes::<32>()));
        self.inner.storage(address, index)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.inner.block_hash(number)
    }
}

/// The `OfflineSources` of `block` from re-executing it on its parent's
/// state (the fallback for blocks without a BAL). Blocking (state reads and
/// trie proofs); run it on a blocking thread.
pub fn sources_by_execution<P, E>(
    provider: &P,
    evm_config: &E,
    chain_id: u64,
    block: &RecoveredBlock<Block>,
) -> Result<OfflineSources>
where
    P: StateProviderFactory + HeaderProvider<Header = alloy_consensus::Header>,
    E: ConfigureEvm<Primitives = EthPrimitives>,
{
    let number = block.header().number();
    let state_provider = provider
        .state_by_block_hash(block.parent_hash())
        .with_context(|| format!("state of parent {}", block.parent_hash()))?;

    let keys: Keys = Arc::default();
    let db = RecordingDb {
        inner: StateProviderDatabase::new(EvmStateProviderAdapter(&*state_provider)),
        keys: keys.clone(),
    };
    let mut executor = evm_config.executor(db);
    executor
        .execute_one_with_state_hook(block, KeyRecorder(keys.clone()))
        .with_context(|| format!("re-executing block {number}"))?;
    let statedb = executor.into_state();
    {
        let mut k = keys.lock().unwrap();
        for (addr, cached) in &statedb.cache.accounts {
            let slots = k.entry(*addr).or_default();
            if let Some(acc) = &cached.account {
                slots.extend(acc.storage.keys().map(|s| B256::from(*s)));
            }
        }
    }
    let lowest_block_hash = statedb.block_hashes.lowest().map(|(n, _)| n);
    let witness = ExecutionWitnessRecord::new(&statedb)
        .into_execution_witness_without_headers(&*state_provider, ExecutionWitnessMode::Legacy)?;

    // Ancestors down to the lowest block BLOCKHASH read.
    let lowest = lowest_block_hash.unwrap_or(number.saturating_sub(1));
    let headers = ancestor_headers(provider, block.parent_hash(), lowest)?;

    let accessed: Accessed = std::mem::take(&mut *keys.lock().unwrap());
    let txs = block.transactions_with_sender().map(|(sender, tx)| (tx, *sender));
    let rpc_witness =
        rust_input_gen::rpc::ExecutionWitness { state: witness.state, codes: witness.codes, keys: witness.keys, headers };
    finish(chain_id, block.sealed_block(), txs, rpc_witness, accessed)
}

/// The `OfflineSources` of `block` from its block access list, without
/// executing it: the BAL names every account and slot the block touches
/// (the guest rebuilds it from its own accesses and checks its hash) and
/// their post-values, which is all the trie proofs need. Codes are a
/// superset (every BAL account's code, in practice all used); ancestors are
/// the parent only unless `all_ancestors` (`assemble::trim` then keeps the
/// ones a pre-check reported).
/// Blocking; run it on a blocking thread.
pub fn sources_from_bal<P>(
    provider: &P,
    chain_id: u64,
    block: &SealedBlock<Block>,
    bal_rlp: &[u8],
    all_ancestors: bool,
) -> Result<OfflineSources>
where
    P: StateProviderFactory + HeaderProvider<Header = alloy_consensus::Header> + Sync,
{
    use alloy_rlp::Decodable;
    use reth_ethereum::trie::HashedPostState;

    let number = block.number;
    let t = std::time::Instant::now();
    let bal = Vec::<alloy_eip7928::AccountChanges>::decode(&mut &bal_rlp[..])
        .map_err(|e| anyhow::anyhow!("decoding the block access list: {e}"))?;
    let state_provider = provider
        .state_by_block_hash(block.parent_hash)
        .with_context(|| format!("state of parent {}", block.parent_hash))?;

    // Read the pre-state and warm the trie pages the proofs will walk, in
    // parallel: on a cold page cache the first proof walk of a block's keys
    // is I/O-bound (0.5-2.5 s sequential, ~70 ms once warm). Each thread
    // takes a share of the accounts with its own provider and proves them
    // (result discarded); the full proof below then runs warm.
    const THREADS: usize = 16;
    let chunk = bal.len().div_ceil(THREADS).max(1);
    let parts: Vec<AccountPart> = std::thread::scope(|scope| -> Result<Vec<AccountPart>> {
        let handles: Vec<_> = bal
            .chunks(chunk)
            .map(|accounts| {
                scope.spawn(move || -> Result<Vec<AccountPart>> {
                    let sp = provider.state_by_block_hash(block.parent_hash)?;
                    let parts = accounts.iter().map(|acc| account_part(&*sp, acc)).collect::<Result<Vec<_>>>()?;
                    let mut warm = HashedPostState::default();
                    for p in &parts {
                        warm.accounts.insert(p.hashed_addr, p.post);
                        warm.storages.insert(p.hashed_addr, p.storage.clone());
                    }
                    sp.witness(Default::default(), warm, ExecutionWitnessMode::Legacy)?;
                    Ok(parts)
                })
            })
            .collect();
        let mut all = Vec::with_capacity(bal.len());
        for h in handles {
            all.extend(h.join().map_err(|_| anyhow::anyhow!("BAL witness thread panicked"))??);
        }
        Ok(all)
    })?;

    let mut accessed = Accessed::new();
    let mut hashed = HashedPostState::default();
    let mut codes = Vec::new();
    let mut code_hashes = std::collections::HashSet::new();
    let mut keys: Vec<alloy_primitives::Bytes> = Vec::new();
    for p in parts {
        hashed.accounts.insert(p.hashed_addr, p.post);
        hashed.storages.insert(p.hashed_addr, p.storage);
        keys.push(p.address.to_vec().into());
        keys.extend(p.slots.iter().map(|s| s.to_vec().into()));
        accessed.insert(p.address, p.slots);
        if let Some((h, code)) = p.code {
            if code_hashes.insert(h) {
                codes.push(code);
            }
        }
    }
    let reads = t.elapsed();
    let slots: usize = accessed.values().map(|s| s.len()).sum();
    let state = state_provider.witness(Default::default(), hashed, ExecutionWitnessMode::Legacy)?;
    let proofs = t.elapsed();

    // The parent, or every depth BLOCKHASH can reach (1..=256): which ones
    // a block reads is only known by executing it, and nearly every block
    // reads none beyond the parent.
    let lowest = if all_ancestors { number.saturating_sub(256) } else { number.saturating_sub(1) };
    let headers = ancestor_headers(provider, block.parent_hash, lowest)?;
    let header_walk = t.elapsed();

    let txs = block.body().transactions.iter().map(|tx| (tx, Address::ZERO));
    let witness = rust_input_gen::rpc::ExecutionWitness { state, codes, keys, headers };
    let sources = finish(chain_id, block, txs, witness, accessed)?;
    tracing::info!(
        number,
        accounts = bal.len(),
        slots,
        ?reads,
        proofs = ?(proofs - reads),
        headers = ?(header_walk - proofs),
        assemble = ?(t.elapsed() - header_walk),
        "BAL witness phases"
    );
    Ok(sources)
}

/// What one BAL account contributes to the witness target and the input.
struct AccountPart {
    address: Address,
    hashed_addr: B256,
    post: Option<reth_ethereum::primitives::Account>,
    storage: reth_ethereum::trie::HashedStorage,
    slots: std::collections::BTreeSet<B256>,
    /// Pre-state bytecode, if the account has code.
    code: Option<(B256, alloy_primitives::Bytes)>,
}

fn account_part(
    state_provider: &dyn reth_ethereum::storage::StateProvider,
    acc: &alloy_eip7928::AccountChanges,
) -> Result<AccountPart> {
    let addr = acc.address;
    let pre = state_provider.basic_account(&addr)?;

    // Post-state account: the pre-state overlaid with the last change of
    // each field (BAL changes are in block-access-index order).
    let mut post = pre.unwrap_or_default();
    if let Some(c) = acc.balance_changes.last() {
        post.balance = c.post_balance;
    }
    if let Some(c) = acc.nonce_changes.last() {
        post.nonce = c.new_nonce;
    }
    if let Some(c) = acc.code_changes.last() {
        post.bytecode_hash = if c.new_code.is_empty() { None } else { Some(alloy_primitives::keccak256(&c.new_code)) };
    }
    let changed = !(acc.balance_changes.is_empty() && acc.nonce_changes.is_empty() && acc.code_changes.is_empty());
    let post = if !changed {
        pre
    } else if post.nonce == 0 && post.balance.is_zero() && post.bytecode_hash.is_none_or(|h| h == KECCAK256_EMPTY) {
        None // EIP-161: an empty account is removed from the trie
    } else {
        Some(post)
    };

    // Storage: changed slots take their last value, read slots their
    // current one.
    let mut slots = std::collections::BTreeSet::new();
    let mut storage = reth_ethereum::trie::HashedStorage::default();
    for sc in &acc.storage_changes {
        let slot = B256::from(sc.slot.to_be_bytes::<32>());
        let value = sc.changes.last().map(|c| c.new_value).unwrap_or_default();
        storage.storage.insert(alloy_primitives::keccak256(slot), value);
        slots.insert(slot);
    }
    for r in &acc.storage_reads {
        let slot = B256::from(r.to_be_bytes::<32>());
        let value = state_provider.storage(addr, slot)?.unwrap_or_default();
        storage.storage.insert(alloy_primitives::keccak256(slot), value);
        slots.insert(slot);
    }

    let code = match pre.and_then(|a| a.bytecode_hash).filter(|h| *h != KECCAK256_EMPTY) {
        Some(h) => {
            let code = state_provider
                .bytecode_by_hash(&h)?
                .with_context(|| format!("bytecode {h} of {addr} not found"))?;
            Some((h, code.original_bytes()))
        }
        None => None,
    };
    Ok(AccountPart { address: addr, hashed_addr: alloy_primitives::keccak256(addr), post, storage, slots, code })
}

/// RLP headers from `parent` back by parent hash (not by number, so a block
/// on a side fork gets its own ancestors) down to block `lowest`.
fn ancestor_headers<P>(provider: &P, parent: B256, lowest: u64) -> Result<Vec<alloy_primitives::Bytes>>
where
    P: HeaderProvider<Header = alloy_consensus::Header>,
{
    let mut out = Vec::new();
    let mut hash = parent;
    loop {
        let header = provider.header(hash)?.with_context(|| format!("ancestor header {hash} not found"))?;
        let n = header.number;
        hash = header.parent_hash;
        let mut buf = Vec::new();
        alloy_rlp::Encodable::encode(&header, &mut buf);
        out.push(buf.into());
        if n <= lowest || n == 0 {
            break;
        }
    }
    Ok(out)
}

fn finish<'a>(
    chain_id: u64,
    block: &SealedBlock<Block>,
    txs: impl Iterator<Item = (&'a reth_ethereum::TransactionSigned, Address)>,
    witness: rust_input_gen::rpc::ExecutionWitness,
    accessed: Accessed,
) -> Result<OfflineSources> {
    debug!(
        number = block.number,
        state_nodes = witness.state.len(),
        codes = witness.codes.len(),
        keys = witness.keys.len(),
        headers = witness.headers.len(),
        accounts = accessed.len(),
        "built execution witness"
    );
    // The encoder writes only the EIP-2718 envelopes (the guest recovers
    // the senders itself), so a sender is informational.
    let txs = txs
        .map(|(tx, sender)| -> Result<(TxEnvelope, Address)> {
            // reth's signed tx is the EIP-2718 envelope with a plain 4844
            // body; re-decode as alloy's `TxEnvelope`.
            let env = TxEnvelope::decode_2718(&mut tx.encoded_2718().as_slice())
                .map_err(|e| anyhow::anyhow!("re-decoding tx: {e}"))?;
            Ok((env, sender))
        })
        .collect::<Result<Vec<_>>>()?;
    let current = rust_input_gen::assemble::rpc_block(
        block.header().clone(),
        txs,
        block.body().withdrawals.as_ref().map(|w| w.to_vec()),
    );
    rust_input_gen::assemble::sources_from_parts(chain_id, current, witness, accessed)
}
