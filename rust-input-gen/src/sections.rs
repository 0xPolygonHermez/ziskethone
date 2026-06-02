//! Per-section encoders. See `BINARY_FORMAT.md` for the on-disk
//! schema each function emits.
//!
//! Phase 4: every section is real; no more placeholders. (StateRoot
//! trie-hint stream remains a Phase-5 stub for now.)

use std::collections::BTreeMap;

use alloy::consensus::TxEnvelope;
use alloy::eips::eip2718::Encodable2718;
use alloy::primitives::{Address, PrimitiveSignature, B256, U256};
use alloy::rpc::types::{Block, BlockTransactions};
use anyhow::Result;
use sha3::{Digest, Keccak256};

use crate::rpc::{Prestate, PrestateDiff};
use crate::writer::Writer;

/// On-wire format version, written in the 4 bytes after the magic.
/// Must match the guest's `kVersion` in `cpp-guest/include/zeg/binary_format.hpp`.
/// v3: dropped the Accounts/Storages sections; the StateRoot section starts
/// with three u64 counts and each `Op::Leaf` carries its key + block-start
/// values, so the guest builds both tables during the old-root walk.
/// v2: single `Op::Branch` opcode (no NodeR/NodeRW); `is_read_only` dropped
/// from the Accounts (now 128 B) and Storages (now 88 B) records — the guest
/// derives read-only-ness dynamically (original == current).
/// v1: StateRoot `Op::Leaf` carries no index (keccak-sorted tables +
/// counter-derived index in the guest).
pub const FORMAT_VERSION: u32 = 3;

/// File magic prefix (8 bytes): 4 B ASCII `"ZEG0"` + 4 B little-endian
/// format version, which also keeps the cursor 8-byte aligned for the
/// sections that follow.
pub fn write_magic(w: &mut Writer) {
    w.bytes(b"ZEG0");
    w.u32_le(FORMAT_VERSION);
    w.assert_aligned();
}

/// Fork identifiers — wire contract with the guest's `ForkId` enum in
/// `cpp-guest/include/zeg/fork.hpp`. Keep the numeric values in sync.
/// The guest derives both the EVM revision and the header field count
/// from this id; `0` (= Unknown) resolves to Prague (mainnet default).
const FORK_BERLIN: u64 = 1;
const FORK_LONDON: u64 = 2;
// FORK_PARIS = 3 exists in the guest enum but is never emitted here:
// Paris and London share the same header structure (16 fields), so the
// live-RPC path can't distinguish them and emits FORK_LONDON for both.
const FORK_SHANGHAI: u64 = 4;
const FORK_CANCUN: u64 = 5;
const FORK_PRAGUE: u64 = 6;
const FORK_OSAKA: u64 = 7;

/// Section 1 — `ConsensusInfo`.
///
/// `current` is the block being executed; `parent` is the block at
/// `current.number - 1`. The `parent_hash` slot carries the parent's
/// **state root** (this guest's convention — see BINARY_FORMAT.md §1).
///
/// `is_osaka` distinguishes Osaka from Prague — they share an identical
/// header structure, so it can't be inferred from `current` and is
/// resolved upstream from the node's `eth_config`.
pub fn write_consensus_info(w: &mut Writer, current: &Block, parent: &Block, is_osaka: bool) {
    let h = &current.header;

    // 0..32  parent_hash ← parent.state_root (this guest's convention)
    w.bytes(parent.header.state_root.as_slice());
    // 32..52 beneficiary
    w.bytes(h.beneficiary.as_slice());
    // 52..56 reserved padding. This slot used to hold a u32
    // `field_count`; the fork is now carried by the 64-bit `fork_id`
    // appended at the end of the prefix (see below), which can also
    // express Osaka — indistinguishable from Prague by field count.
    w.pad(4);
    // 56..64 number
    w.u64_le(h.number);
    // 64..72 gas_limit
    w.u64_le(h.gas_limit);
    // 72..80 timestamp
    w.u64_le(h.timestamp);
    // 80..88 extra_data_len  (must be ≤ 32; truncate if a non-mainnet
    // block somehow exceeds it — Pectra mainnet caps at 32).
    let ed_len = h.extra_data.len().min(32);
    w.u64_le(ed_len as u64);
    // 88..120 extra_data buffer (zero-padded to 32 B)
    w.bytes(&h.extra_data[..ed_len]);
    w.pad(32 - ed_len);
    // 120..152 prev_randao  (= header.mix_hash post-merge)
    w.bytes(h.mix_hash.as_slice());
    // 152..184 parent_beacon_block_root (zero pre-Cancun)
    w.bytes(h.parent_beacon_block_root.unwrap_or_default().as_slice());
    // 184..216 base_fee_per_gas (uint256be; zero pre-London)
    let base_fee = U256::from(h.base_fee_per_gas.unwrap_or(0));
    w.bytes(&base_fee.to_be_bytes::<32>());
    // 216..224 withdrawals_count
    let with_count = current.withdrawals.as_ref().map(|wd| wd.len()).unwrap_or(0);
    w.u64_le(with_count as u64);
    // 224..232 excess_blob_gas (zero pre-Cancun)
    w.u64_le(h.excess_blob_gas.unwrap_or(0));
    // 232..264 requests_hash (zero pre-Pectra). Declared value from the
    // block header; cpp-guest cross-checks its recomputed value against
    // this and fatals on mismatch (EIP-7685 validity).
    w.bytes(h.requests_hash.unwrap_or_default().as_slice());
    // 264..296 difficulty (uint256be) — pre-Merge PoW difficulty.
    //          post-Merge always 0, but EEST pre-Paris fixtures
    //          (Berlin/London modexp tests) pin real values.
    w.bytes(&h.difficulty.to_be_bytes::<32>());
    // 296..304 nonce (8 B) — pre-Merge PoW nonce; post-Merge always 0.
    w.bytes(h.nonce.as_slice());
    // 304..336 ommers_hash (bytes32) — kEmptyOmmersHash post-Merge,
    //          but pre-Merge headers can have non-empty ommers.
    w.bytes(h.ommers_hash.as_slice());
    // 336..344 fork_id (u64-le). Derived from the header structure, with
    // Osaka layered on top via the upstream `is_osaka` flag (Osaka adds
    // no header field over Prague, so it can't be inferred here). The
    // guest maps this to the EVM revision + header field count.
    let fork_id: u64 = if is_osaka {
        FORK_OSAKA
    } else if h.requests_hash.is_some() {
        FORK_PRAGUE
    } else if h.parent_beacon_block_root.is_some() {
        FORK_CANCUN
    } else if h.withdrawals_root.is_some() {
        FORK_SHANGHAI
    } else if h.base_fee_per_gas.is_some() {
        FORK_LONDON
    } else {
        FORK_BERLIN
    };
    w.u64_le(fork_id);
    w.assert_aligned();

    // Withdrawal records × 48 B each (EIP-4895).
    if let Some(wds) = &current.withdrawals {
        for wd in wds.iter() {
            //  0..8  index
            w.u64_le(wd.index);
            //  8..16 validator_index
            w.u64_le(wd.validator_index);
            // 16..36 address
            w.bytes(wd.address.as_slice());
            // 36..40 pad
            w.pad(4);
            // 40..48 amount_gwei
            w.u64_le(wd.amount);
        }
    }
    w.assert_aligned();
}

/// Section 2 — `Transactions`.
///
/// For each tx in `current.transactions`, writes the per-tx record:
///   `u64 envelope_size` + 64 B sender pubkey + envelope bytes
///   + pad-to-8 + (if Type-4) N × 64 B auth-signer pubkeys.
///
/// `current` must have been fetched with `BlockTransactionsKind::Full`
/// — i.e. via `Client::block_full`.
pub fn write_transactions(w: &mut Writer, current: &Block) -> Result<()> {
    let txs: &[_] = match &current.transactions {
        BlockTransactions::Full(v) => v.as_slice(),
        _ => &[],
    };

    w.u64_le(txs.len() as u64);
    for tx in txs {
        let env: &TxEnvelope = &tx.inner;

        // EIP-2718 canonical wire envelope (legacy = raw RLP list,
        // typed = `type_byte || rlp(...)`).
        let mut env_buf = Vec::with_capacity(env.encode_2718_len());
        env.encode_2718(&mut env_buf);

        // Recover the sender's uncompressed pubkey (64 B, x || y, BE).
        let sender_pk = recover_pubkey(env.signature(), &env.signature_hash())?;

        w.u64_le(env_buf.len() as u64);
        w.bytes(&sender_pk);
        w.bytes(&env_buf);
        w.pad_to_8();

        // EIP-7702 (Type-4) only: append one 64 B pubkey per
        // authorization in the auth list. The cpp-guest reads them in
        // the same order — see `transactions.cpp:540-551`.
        //
        // For auths whose signature is INVALID (bad parity, s out of
        // range, etc.), write 64 zero bytes as a sentinel. Per EIP-7702,
        // invalid auths must be SKIPPED — the block-level tx still
        // executes, only the auth itself is a no-op. cpp-guest
        // detects the all-zero sentinel and treats the auth as
        // unverifiable (= skip). Fixtures like
        // test_valid_tx_invalid_auth_signature exercise this path.
        if let TxEnvelope::Eip7702(signed) = env {
            for auth in &signed.tx().authorization_list {
                let auth_pk: [u8; 64] = match auth.signature() {
                    Ok(sig) => recover_pubkey(&sig, &auth.inner().signature_hash())
                        .unwrap_or([0u8; 64]),
                    Err(_) => [0u8; 64],
                };
                w.bytes(&auth_pk);
            }
            // 64 B is already 8-aligned; no extra pad needed.
        }
    }
    w.assert_aligned();
    Ok(())
}

/// Recover the 64-byte uncompressed secp256k1 pubkey (x || y, BE)
/// that signed `prehash` to produce `sig`.
fn recover_pubkey(sig: &PrimitiveSignature, prehash: &B256) -> Result<[u8; 64]> {
    let vk = sig
        .recover_from_prehash(prehash)
        .map_err(|e| anyhow::anyhow!("pubkey recovery failed: {e}"))?;
    // SEC1 uncompressed encoding: 65 bytes = 0x04 || x || y. Drop the
    // tag byte to get the 64 B x || y the cpp-guest expects.
    let point = vk.to_encoded_point(false);
    let bytes = point.as_bytes();
    anyhow::ensure!(
        bytes.len() == 65 && bytes[0] == 0x04,
        "unexpected SEC1 encoding (len={}, tag={:#04x})",
        bytes.len(),
        bytes.first().copied().unwrap_or(0),
    );
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes[1..]);
    Ok(out)
}

// ----- keccak helper used by Accounts + Contracts ----------------------------

pub const EMPTY_CODE_HASH: B256 = B256::new([
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
    0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
    0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
]);

fn keccak256(bytes: &[u8]) -> B256 {
    let mut hasher = Keccak256::new();
    hasher.update(bytes);
    B256::from_slice(&hasher.finalize())
}

/// Block-start (original) account fields for one address — the values
/// that used to populate the now-removed `Accounts` section, sourced
/// identically. The StateRoot encoder embeds these in each state
/// `Op::Leaf` payload; the guest builds its Accounts table from them.
///
/// Field sourcing:
///   * balance, nonce, code   ← prestate (block-start). Falls back to
///                              diff.pre (also a block-start value) if
///                              the address is only present there;
///                              else zero/empty defaults (newly created
///                              — was non-existent pre-block).
///   * code_hash              ← keccak256(code) or EMPTY_CODE_HASH.
pub fn account_original_fields(
    addr: &Address,
    prestate: &Prestate,
    diff: &PrestateDiff,
) -> (U256, u64, B256) {
    // Created-during-block: present in diff.post but NOT in diff.pre. The
    // non-diff prestate may carry post-creation values (the first tx that
    // READ the account ran AFTER the CREATE), but the block-START values
    // must be empty for the old-root reconstruction to match.
    let created_this_block =
        !diff.pre.contains_key(addr) && diff.post.contains_key(addr);

    if created_this_block {
        return (U256::ZERO, 0u64, EMPTY_CODE_HASH);
    }
    let ps_main = prestate.get(addr);
    let ps_fallback = diff.pre.get(addr);
    let balance = ps_main.and_then(|p| p.balance)
        .or_else(|| ps_fallback.and_then(|p| p.balance))
        .unwrap_or(U256::ZERO);
    let nonce = ps_main.and_then(|p| p.nonce)
        .or_else(|| ps_fallback.and_then(|p| p.nonce))
        .unwrap_or(0);
    let code = ps_main.and_then(|p| p.code.as_ref())
        .or_else(|| ps_fallback.and_then(|p| p.code.as_ref()));
    let code_hash = match code {
        Some(c) if !c.is_empty() => keccak256(c),
        _ => EMPTY_CODE_HASH,
    };
    (balance, nonce, code_hash)
}

/// Section 4 — `Contracts`.
///
/// One record per unique deployed bytecode the block touches. Sources:
///   * `prestate.code` — block-start code for every contract whose
///     code the tx prestate captured.
///   * `diff.post[addr].code` — newly-deployed contracts (so calls
///     into the new address later in the block can find their code).
///   * EIP-7702 delegation stubs (`0xef0100 || delegate`, 23 B) —
///     for every authorization in every Type-4 tx, regardless of
///     whether the auth's validity checks pass. The cpp-guest
///     computes the hash of this stub when it processes the auth and
///     then looks it up later via `Contracts::by_hash` when something
///     CALLs the delegated EOA.
///
/// Deduplicated by `keccak256(code)`.
pub fn write_contracts(
    w: &mut Writer,
    prestate: &Prestate,
    diff: &PrestateDiff,
    current: &Block,
) -> Result<()> {
    use alloy::primitives::Bytes;
    let mut by_hash: BTreeMap<B256, Bytes> = BTreeMap::new();

    let insert = |dst: &mut BTreeMap<B256, Bytes>, code: Bytes| {
        if code.is_empty() {
            return;
        }
        let h = keccak256(&code);
        if h == EMPTY_CODE_HASH {
            return;
        }
        dst.entry(h).or_insert(code);
    };

    for ps in prestate.values() {
        if let Some(c) = &ps.code {
            insert(&mut by_hash, c.clone());
        }
    }
    for ps in diff.post.values() {
        if let Some(c) = &ps.code {
            insert(&mut by_hash, c.clone());
        }
    }

    // EIP-7702 delegation stubs: 0xef0100 || delegate, for every auth.
    if let BlockTransactions::Full(txs) = &current.transactions {
        for tx in txs {
            if let TxEnvelope::Eip7702(signed) = &tx.inner {
                for auth in &signed.tx().authorization_list {
                    let delegate = auth.inner().address;
                    let mut stub = [0u8; 23];
                    stub[0] = 0xef; stub[1] = 0x01; stub[2] = 0x00;
                    stub[3..].copy_from_slice(delegate.as_slice());
                    insert(&mut by_hash, Bytes::from(stub.to_vec()));
                }
            }
        }
    }

    w.u64_le(by_hash.len() as u64);
    for code in by_hash.values() {
        w.u64_le(code.len() as u64);
        w.bytes(code);
        w.pad_to_8();
    }
    w.assert_aligned();
    Ok(())
}

/// Block-start (original) value for every touched (address, slot) — the
/// data that used to populate the now-removed `Storages` section, sourced
/// identically. The StateRoot encoder embeds each value in its storage
/// `Op::Leaf` payload; the guest builds its Storages table from them.
///
/// Block-start value prefers prestate → diff.pre → zero (a slot only in
/// diff.post is newly created, so its pre-block value is zero).
pub fn storage_original_values(
    prestate: &Prestate,
    diff: &PrestateDiff,
) -> BTreeMap<(Address, B256), B256> {
    let mut value_of: BTreeMap<(Address, B256), B256> = BTreeMap::new();
    for (addr, ps) in prestate {
        for (slot, value) in &ps.storage {
            value_of.insert((*addr, *slot), *value);
        }
    }
    for (addr, info) in &diff.pre {
        for (slot, value) in &info.storage {
            value_of.entry((*addr, *slot)).or_insert(*value);
        }
    }
    for (addr, info) in &diff.post {
        for slot in info.storage.keys() {
            value_of.entry((*addr, *slot)).or_insert(B256::ZERO);
        }
    }
    value_of
}

/// Section 6 — `PreviousBlocks`.
///
/// `ancestors[0]` is the parent (block `N-1`), `ancestors[1]` the
/// grandparent, etc. Each record is 728 B with all 21 Pectra header
/// fields. Pre-Pectra blocks have zero-defaulted optional fields.
pub fn write_previous_blocks(w: &mut Writer, ancestors: &[Block]) {
    w.u64_le(ancestors.len() as u64);
    for blk in ancestors {
        let h = &blk.header;

        //   0..32  parent_hash
        w.bytes(h.parent_hash.as_slice());
        //  32..64  ommers_hash
        w.bytes(h.ommers_hash.as_slice());
        //  64..84  coinbase
        w.bytes(h.beneficiary.as_slice());
        //  84..88  field_count (u32-le): the number of fields cpp-guest
        //          should RLP-encode for this ancestor's header. Header
        //          layout grew across hardforks; without an explicit
        //          marker, a Cancun block with no blob transactions and
        //          no CL (test-fixture scenario, parent_beacon_block_root
        //          = 0) is indistinguishable from a pre-Cancun block —
        //          both have all-zero trailing fields. Was a 4-byte pad
        //          (always 0) → backward-compatible: cpp-guest treats 0
        //          as 21 (Pectra default), matching mainnet replays.
        let field_count: u32 = if h.requests_hash.is_some() {
            21
        } else if h.parent_beacon_block_root.is_some() {
            20
        } else if h.withdrawals_root.is_some() {
            17
        } else if h.base_fee_per_gas.is_some() {
            16
        } else {
            15
        };
        w.u32_le(field_count);
        //  88..120 state_root
        w.bytes(h.state_root.as_slice());
        // 120..152 transactions_root
        w.bytes(h.transactions_root.as_slice());
        // 152..184 receipts_root
        w.bytes(h.receipts_root.as_slice());
        // 184..440 logs_bloom (256 B)
        w.bytes(h.logs_bloom.as_slice());
        // 440..472 difficulty (uint256be)
        w.bytes(&h.difficulty.to_be_bytes::<32>());
        // 472..480 number
        w.u64_le(h.number);
        // 480..488 gas_limit
        w.u64_le(h.gas_limit);
        // 488..496 gas_used
        w.u64_le(h.gas_used);
        // 496..504 timestamp
        w.u64_le(h.timestamp);
        // 504..512 extra_data_len (clamped to 32)
        let ed_len = h.extra_data.len().min(32);
        w.u64_le(ed_len as u64);
        // 512..544 extra_data buffer (zero-padded to 32 B)
        w.bytes(&h.extra_data[..ed_len]);
        w.pad(32 - ed_len);
        // 544..576 prev_randao (mix_hash)
        w.bytes(h.mix_hash.as_slice());
        // 576..584 nonce — 8 raw bytes (Ethereum fixed-width bytestring)
        w.bytes(h.nonce.as_slice());
        // 584..616 base_fee_per_gas (uint256be; zero pre-London)
        let bf = U256::from(h.base_fee_per_gas.unwrap_or(0));
        w.bytes(&bf.to_be_bytes::<32>());
        // 616..648 withdrawals_root (zero pre-Shanghai)
        w.bytes(h.withdrawals_root.unwrap_or_default().as_slice());
        // 648..656 blob_gas_used (zero pre-Cancun)
        w.u64_le(h.blob_gas_used.unwrap_or(0));
        // 656..664 excess_blob_gas (zero pre-Cancun)
        w.u64_le(h.excess_blob_gas.unwrap_or(0));
        // 664..696 parent_beacon_block_root (zero pre-Cancun)
        w.bytes(h.parent_beacon_block_root.unwrap_or_default().as_slice());
        // 696..728 requests_hash (zero pre-Pectra)
        w.bytes(h.requests_hash.unwrap_or_default().as_slice());

        w.assert_aligned();
    }
}
