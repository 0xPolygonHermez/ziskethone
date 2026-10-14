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
/// verifying it: the BAL names every account and slot the block touches
/// (the guest rebuilds it from its own accesses and checks its hash) and
/// their post-values, which is all the trie proofs need.
///
/// - A: 16 threads read the pre-state of every BAL account, slot and code
///   (while the senders are recovered).
/// - B and C, concurrently: B proves a share of the accounts per thread to
///   warm the trie pages (the first, cold proof walk is I/O-bound); C runs
///   every transaction in parallel on the pre-state + the BAL as of its
///   index (revm's BAL state), only to record the BLOCKHASH numbers (and,
///   as a cross-check, the codes) execution uses.
/// - D: the full proof, warm.
///
/// Codes are every BAL account's pre-state code: always a superset of what
/// the guest loads (an account whose code is loaded is accessed, hence in
/// the BAL). Ancestors are the parent and the BLOCKHASH targets.
/// Blocking; run it on a blocking thread.
pub fn sources_from_bal<P, E>(
    provider: &P,
    evm_config: &E,
    chain_id: u64,
    block: &SealedBlock<Block>,
    bal_rlp: &[u8],
) -> Result<OfflineSources>
where
    P: StateProviderFactory + HeaderProvider<Header = alloy_consensus::Header> + Sync,
    E: ConfigureEvm<Primitives = EthPrimitives> + Sync,
{
    use alloy_rlp::Decodable;
    use reth_ethereum::trie::HashedPostState;

    let number = block.number;
    let t = std::time::Instant::now();
    let bal = Vec::<alloy_eip7928::AccountChanges>::decode(&mut &bal_rlp[..])
        .map_err(|e| anyhow::anyhow!("decoding the block access list: {e}"))?;

    // A: pre-state reads, and the senders, in parallel. (Warming the trie
    // pages in the same threads right after each share's reads was slower:
    // the proof walks' random I/O delays the remaining reads, which gate C.)
    const THREADS: usize = 16;
    let chunk = bal.len().div_ceil(THREADS).max(1);
    let txs = &block.body().transactions;
    let (parts, senders) = std::thread::scope(|scope| -> Result<(Vec<AccountPart>, Vec<Address>)> {
        let readers: Vec<_> = bal
            .chunks(chunk)
            .map(|accounts| {
                scope.spawn(move || -> Result<Vec<AccountPart>> {
                    let sp = provider.state_by_block_hash(block.parent_hash)?;
                    accounts.iter().map(|acc| account_part(&*sp, acc)).collect()
                })
            })
            .collect();
        let tx_chunk = txs.len().div_ceil(THREADS).max(1);
        let recoverers: Vec<_> = txs
            .chunks(tx_chunk)
            .map(|txs| {
                scope.spawn(move || -> Result<Vec<Address>> {
                    use reth_ethereum::primitives::SignerRecoverable;
                    txs.iter()
                        .map(|tx| tx.recover_signer_unchecked().map_err(|e| anyhow::anyhow!("recovering a sender: {e}")))
                        .collect()
                })
            })
            .collect();
        let mut parts = Vec::with_capacity(bal.len());
        for h in readers {
            parts.extend(h.join().map_err(|_| anyhow::anyhow!("BAL read thread panicked"))??);
        }
        let mut senders = Vec::with_capacity(txs.len());
        for h in recoverers {
            senders.extend(h.join().map_err(|_| anyhow::anyhow!("sender thread panicked"))??);
        }
        Ok((parts, senders))
    })?;
    let reads = t.elapsed();

    let pre = PreState::from_parts(&parts);
    let revm_bal = std::sync::Arc::new(
        revm::state::bal::Bal::clone_from_alloy(&bal).map_err(|e| anyhow::anyhow!("BAL to revm: {e:?}"))?,
    );

    // B and C concurrently: warm the trie pages while executing.
    let (exec, warm) = std::thread::scope(|scope| -> Result<(ExecRecord, std::time::Duration)> {
        let warmers: Vec<_> = parts
            .chunks(parts.len().div_ceil(THREADS).max(1))
            .map(|parts| {
                scope.spawn(move || -> Result<()> {
                    let sp = provider.state_by_block_hash(block.parent_hash)?;
                    let mut target = HashedPostState::default();
                    for p in parts {
                        target.accounts.insert(p.hashed_addr, p.post);
                        target.storages.insert(p.hashed_addr, p.storage.clone());
                    }
                    sp.witness(Default::default(), target, ExecutionWitnessMode::Legacy)?;
                    Ok(())
                })
            })
            .collect();
        let exec = execute_with_bal(provider, evm_config, block, &senders, &pre, &revm_bal, 8)?;
        for h in warmers {
            h.join().map_err(|_| anyhow::anyhow!("warm-up thread panicked"))??;
        }
        Ok((exec, t.elapsed()))
    })?;

    // D: the full proof, warm.
    let state_provider = provider
        .state_by_block_hash(block.parent_hash)
        .with_context(|| format!("state of parent {}", block.parent_hash))?;
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
                codes.push(code.original_bytes());
            }
        }
    }
    let slots: usize = accessed.values().map(|s| s.len()).sum();
    let state = state_provider.witness(Default::default(), hashed, ExecutionWitnessMode::Legacy)?;
    let proofs = t.elapsed();

    // The parent and every BLOCKHASH target execution read.
    let lowest = exec.block_hashes.iter().copied().min().unwrap_or(number.saturating_sub(1)).min(number.saturating_sub(1));
    let mut headers = Vec::new();
    for (n, rlp) in ancestor_headers_numbered(provider, block.parent_hash, lowest)? {
        if n + 1 == number || exec.block_hashes.contains(&n) {
            headers.push(rlp);
        }
    }

    let exec_codes_outside: usize = exec.codes.iter().filter(|h| !code_hashes.contains(*h)).count();
    let witness = rust_input_gen::rpc::ExecutionWitness { state, codes, keys, headers };
    let txs = txs.iter().zip(senders.iter().copied());
    let sources = finish(chain_id, block, txs, witness, accessed)?;
    tracing::info!(
        number,
        accounts = bal.len(),
        slots,
        txs = senders_len(&sources),
        ?reads,
        exec = ?exec.elapsed,
        exec_failed = exec.failed,
        exec_ok = exec.ok,
        db_misses = exec.misses,
        blockhash = ?exec.block_hashes,
        codes_in_input = code_hashes.len(),
        codes_executed = exec.codes.len(),
        codes_executed_outside_input = exec_codes_outside,
        warm = ?(warm - reads),
        proofs = ?(proofs - warm),
        "BAL witness phases"
    );
    Ok(sources)
}

fn senders_len(s: &OfflineSources) -> usize {
    match &s.current.transactions {
        alloy_rpc_types_eth::BlockTransactions::Full(v) => v.len(),
        _ => 0,
    }
}

/// The pre-state of every BAL key, for executing the block in memory.
#[derive(Default)]
struct PreState {
    accounts: std::collections::HashMap<Address, Option<reth_ethereum::primitives::Account>>,
    storage: std::collections::HashMap<(Address, B256), alloy_primitives::U256>,
    codes: std::collections::HashMap<B256, Bytecode>,
}

impl PreState {
    fn from_parts(parts: &[AccountPart]) -> Self {
        let mut s = Self::default();
        for p in parts {
            s.accounts.insert(p.address, p.pre);
            for (slot, v) in &p.pre_storage {
                s.storage.insert((p.address, *slot), *v);
            }
            if let Some((h, code)) = &p.code {
                s.codes.insert(*h, code.clone());
            }
        }
        s
    }
}

/// What executing the block recorded.
#[derive(Default)]
struct ExecRecord {
    block_hashes: std::collections::BTreeSet<u64>,
    codes: std::collections::HashSet<B256>,
    /// Reads outside the pre-state: keys the BAL didn't declare.
    misses: usize,
    /// Transactions that failed (an invalid block, judged by reth).
    failed: usize,
    /// Transactions run.
    ok: usize,
    elapsed: std::time::Duration,
}

/// The pre-state from memory (a miss falls back to the parent state and is
/// counted), recording the BLOCKHASH numbers and the codes loaded.
struct MemDb<'a> {
    pre: &'a PreState,
    fallback: reth_ethereum::storage::StateProviderBox,
    rec: ExecRecord,
}

impl std::fmt::Debug for MemDb<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MemDb")
    }
}

impl Database for MemDb<'_> {
    type Error = reth_ethereum::provider::ProviderError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let acc = match self.pre.accounts.get(&address) {
            Some(a) => *a,
            None => {
                self.rec.misses += 1;
                self.fallback.basic_account(&address)?
            }
        };
        Ok(acc.map(|a| AccountInfo {
            balance: a.balance,
            nonce: a.nonce,
            code_hash: a.bytecode_hash.unwrap_or(KECCAK256_EMPTY),
            // Not loaded: revm then fetches it with `code_by_hash` (the
            // default is an empty code, which would skip execution).
            code: None,
            ..Default::default()
        }))
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.rec.codes.insert(code_hash);
        if let Some(c) = self.pre.codes.get(&code_hash) {
            return Ok(c.clone());
        }
        self.rec.misses += 1;
        Ok(self.fallback.bytecode_by_hash(&code_hash)?.map(|c| c.0).unwrap_or_default())
    }

    fn storage(&mut self, address: Address, index: alloy_primitives::U256) -> Result<alloy_primitives::U256, Self::Error> {
        let slot = B256::from(index.to_be_bytes::<32>());
        if let Some(v) = self.pre.storage.get(&(address, slot)) {
            return Ok(*v);
        }
        self.rec.misses += 1;
        Ok(self.fallback.storage(address, slot)?.unwrap_or_default())
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.rec.block_hashes.insert(number);
        Ok(self.fallback.block_hash(number)?.unwrap_or_default())
    }
}

/// Run every transaction of `block` on `threads` workers, each on the
/// pre-state + the BAL as of the transaction's index (revm's BAL state),
/// as reth's BAL executor does; results are dropped.
fn execute_with_bal<P, E>(
    provider: &P,
    evm_config: &E,
    block: &SealedBlock<Block>,
    senders: &[Address],
    pre: &PreState,
    bal: &std::sync::Arc<revm::state::bal::Bal>,
    threads: usize,
) -> Result<ExecRecord>
where
    P: StateProviderFactory + Sync,
    E: ConfigureEvm<Primitives = EthPrimitives> + Sync,
{
    use alloy_evm::block::BlockExecutor;
    use alloy_evm::Evm as _;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let t = std::time::Instant::now();
    let evm_env = evm_config.evm_env(block.header()).map_err(|e| anyhow::anyhow!("evm env: {e:?}"))?;
    let txs = &block.body().transactions;
    let next = AtomicUsize::new(0);
    let records = std::thread::scope(|scope| -> Result<Vec<ExecRecord>> {
        let workers: Vec<_> = (0..threads.min(txs.len()).max(1))
            .map(|_| {
                let (evm_env, next) = (evm_env.clone(), &next);
                scope.spawn(move || -> Result<ExecRecord> {
                    let ctx = evm_config.context_for_block(block).map_err(|e| anyhow::anyhow!("block ctx: {e:?}"))?;
                    let mut db = MemDb { pre, fallback: provider.state_by_block_hash(block.parent_hash)?, rec: ExecRecord::default() };
                    let (mut failed, mut ok) = (0, 0);
                    'worker: loop {
                        let mut state = reth_ethereum::evm::revm::db::State::builder()
                            .with_database(&mut db)
                            .with_bal(bal.clone())
                            .with_bundle_update()
                            .build();
                        let evm = evm_config.evm_with_env(&mut state, evm_env.clone());
                        let mut executor = evm_config.create_executor_with_state(evm, ctx.clone());
                        loop {
                            let i = next.fetch_add(1, Ordering::Relaxed);
                            if i >= txs.len() {
                                break 'worker;
                            }
                            executor
                                .evm_mut()
                                .db_mut()
                                .set_bal_index(alloy_eip7928::BlockAccessIndex::from_tx_index(i as u64));
                            let tx = alloy_consensus::transaction::Recovered::new_unchecked(&txs[i], senders[i]);
                            match executor.execute_transaction_without_commit(tx) {
                                Ok(_) => ok += 1,
                                Err(e) => {
                                    if failed == 0 {
                                        tracing::warn!(tx = i, "BAL execution: {e}");
                                    }
                                    // The executor isn't reusable after an error.
                                    failed += 1;
                                    break;
                                }
                            }
                        }
                    }
                    let mut rec = std::mem::take(&mut db.rec);
                    rec.failed = failed;
                    rec.ok = ok;
                    Ok(rec)
                })
            })
            .collect();
        workers.into_iter().map(|h| h.join().map_err(|_| anyhow::anyhow!("execution thread panicked"))?).collect()
    })?;
    let mut out = ExecRecord::default();
    for r in records {
        out.block_hashes.extend(r.block_hashes);
        out.codes.extend(r.codes);
        out.misses += r.misses;
        out.failed += r.failed;
        out.ok += r.ok;
    }
    out.elapsed = t.elapsed();
    Ok(out)
}

/// What one BAL account contributes to the witness target, the pre-state
/// and the input.
struct AccountPart {
    address: Address,
    hashed_addr: B256,
    pre: Option<reth_ethereum::primitives::Account>,
    post: Option<reth_ethereum::primitives::Account>,
    /// Hashed slots → post-values (the witness target).
    storage: reth_ethereum::trie::HashedStorage,
    /// Every changed or read slot → its pre-value.
    pre_storage: Vec<(B256, alloy_primitives::U256)>,
    slots: std::collections::BTreeSet<B256>,
    /// Pre-state bytecode, if the account has code.
    code: Option<(B256, Bytecode)>,
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
    // current one; both need their pre-value for execution.
    let mut slots = std::collections::BTreeSet::new();
    let mut storage = reth_ethereum::trie::HashedStorage::default();
    let mut pre_storage = Vec::new();
    for sc in &acc.storage_changes {
        let slot = B256::from(sc.slot.to_be_bytes::<32>());
        let value = sc.changes.last().map(|c| c.new_value).unwrap_or_default();
        storage.storage.insert(alloy_primitives::keccak256(slot), value);
        pre_storage.push((slot, state_provider.storage(addr, slot)?.unwrap_or_default()));
        slots.insert(slot);
    }
    for r in &acc.storage_reads {
        let slot = B256::from(r.to_be_bytes::<32>());
        let value = state_provider.storage(addr, slot)?.unwrap_or_default();
        storage.storage.insert(alloy_primitives::keccak256(slot), value);
        pre_storage.push((slot, value));
        slots.insert(slot);
    }

    let code = match pre.and_then(|a| a.bytecode_hash).filter(|h| *h != KECCAK256_EMPTY) {
        Some(h) => {
            let code = state_provider
                .bytecode_by_hash(&h)?
                .with_context(|| format!("bytecode {h} of {addr} not found"))?;
            Some((h, code.0))
        }
        None => None,
    };
    Ok(AccountPart {
        address: addr,
        hashed_addr: alloy_primitives::keccak256(addr),
        pre,
        post,
        storage,
        pre_storage,
        slots,
        code,
    })
}

/// `ancestor_headers` with each header's number.
fn ancestor_headers_numbered<P>(provider: &P, parent: B256, lowest: u64) -> Result<Vec<(u64, alloy_primitives::Bytes)>>
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
        out.push((n, buf.into()));
        if n <= lowest || n == 0 {
            break;
        }
    }
    Ok(out)
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
