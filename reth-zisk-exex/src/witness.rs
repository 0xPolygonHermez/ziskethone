//! The ZEG0 guest input of a block, built in-process from the node's state:
//! the same execution witness `debug_executionWitness` returns, plus every
//! account and slot the block accesses (which `input-gen` gets from the
//! prestate tracer), handed to `rust_input_gen::assemble`.

use std::sync::{Arc, Mutex};

use alloy_consensus::{BlockHeader as _, TxEnvelope};
use alloy_eips::eip2718::{Decodable2718, Encodable2718};
use alloy_primitives::{Address, B256};
use anyhow::{Context, Result};
use reth_ethereum::evm::primitives::{execute::Executor, ConfigureEvm};
use revm::database::OnStateHook;
use reth_ethereum::evm::revm::database::StateProviderDatabase;
use reth_ethereum::evm::revm::witness::ExecutionWitnessRecord;
use reth_ethereum::primitives::RecoveredBlock;
use reth_ethereum::provider::{HeaderProvider, StateProviderFactory};
use reth_ethereum::storage::EvmStateProviderAdapter;
use reth_ethereum::{Block, EthPrimitives};
use reth_trie_common::ExecutionWitnessMode;
use revm::bytecode::Bytecode;
use revm::state::AccountInfo;
use revm::Database;
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

/// Re-execute `block` on its parent's state and encode its ZEG0 input.
/// Blocking (state reads and trie proofs); run it on a blocking thread.
pub fn build_input<P, E>(
    provider: &P,
    evm_config: &E,
    chain_id: u64,
    block: &RecoveredBlock<Block>,
) -> Result<Vec<u8>>
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
    let mut witness = ExecutionWitnessRecord::new(&statedb)
        .into_execution_witness_without_headers(&*state_provider, ExecutionWitnessMode::Legacy)?;

    // Ancestor headers by parent hash (not by number, so a block on a side
    // fork gets its own ancestors): the parent, down to the lowest block
    // BLOCKHASH read.
    let lowest = lowest_block_hash.unwrap_or(number.saturating_sub(1));
    let mut hash = block.parent_hash();
    loop {
        let header = provider
            .header(hash)?
            .with_context(|| format!("ancestor header {hash} not found"))?;
        let n = header.number;
        hash = header.parent_hash;
        let mut buf = Vec::new();
        alloy_rlp::Encodable::encode(&header, &mut buf);
        witness.headers.push(buf.into());
        if n <= lowest || n == 0 {
            break;
        }
    }

    let accessed: Accessed = std::mem::take(&mut *keys.lock().unwrap());
    debug!(
        number,
        state_nodes = witness.state.len(),
        codes = witness.codes.len(),
        keys = witness.keys.len(),
        headers = witness.headers.len(),
        accounts = accessed.len(),
        "built execution witness"
    );

    let current = rust_input_gen::assemble::rpc_block(
        block.header().clone(),
        block
            .transactions_with_sender()
            .map(|(sender, tx)| -> Result<(TxEnvelope, Address)> {
                // reth's signed tx is the EIP-2718 envelope with a plain
                // 4844 body; re-decode as alloy's `TxEnvelope`.
                let env = TxEnvelope::decode_2718(&mut tx.encoded_2718().as_slice())
                    .map_err(|e| anyhow::anyhow!("re-decoding tx: {e}"))?;
                Ok((env, *sender))
            })
            .collect::<Result<Vec<_>>>()?,
        block.body().withdrawals.as_ref().map(|w| w.to_vec()),
    );
    let rpc_witness = rust_input_gen::rpc::ExecutionWitness {
        state: witness.state,
        codes: witness.codes,
        keys: witness.keys,
        headers: witness.headers,
    };
    let sources = rust_input_gen::assemble::sources_from_parts(chain_id, current, rpc_witness, accessed)?;
    rust_input_gen::offline::encode_binary(&sources)
}
