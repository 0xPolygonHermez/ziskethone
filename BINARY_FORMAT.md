# Binary Input Format

This document defines the on-disk binary layout the C++ ZisK Ethereum guest
(`cpp-guest`) consumes. The format is produced by the prover (eventually by
`rust-input-gen`) and read by [`main()`](cpp-guest/src/main.cpp) via
`read_input_stream(argv[1])`.

## Design goals

- **Zero-parse on the guest side.** The guest reads the file into one
  8-byte-aligned buffer and walks it with a cursor; fields with fixed
  offsets are accessed by raw pointer cast.
- **8-byte alignment everywhere.** Every record / variable section is
  sized to a multiple of 8 bytes (with zero padding where needed) so the
  cursor stays 8-byte aligned and `std::assume_aligned<8>` is sound on
  every typed read.
- **Little-endian** for all multi-byte integers (`u32`, `u64`). Hashes,
  addresses, and `uint256be` keep their canonical Ethereum byte order
  (32-byte big-endian for `uint256`, 20-byte raw for addresses).
- **Length-prefixed sections.** Every variable-length section starts
  with a `u64` count so the guest can iterate without an out-of-band
  table of contents.

## Top-level layout

The file is one contiguous byte stream, consumed left-to-right:

```
+---------------------------+  offset 0
|  Magic prefix (8 B)       |
+---------------------------+
|  ConsensusInfo            |
+---------------------------+
|  Transactions             |
+---------------------------+
|  Contracts                |
+---------------------------+
|  PreviousBlocks           |
+---------------------------+
|  StateRoot trie hints     |
+---------------------------+
```

The Accounts and Storages tables are no longer standalone sections: as
of version `3` the guest builds them while walking the StateRoot trie
hints (each `Op::Leaf` carries the key + block-start values), so they are
described under Section 7 rather than as top-level sections.

No padding between sections — each section's last record is itself
sized to a multiple of 8, so the next section starts 8-byte aligned.

## Section 0 — Magic prefix (8 bytes)

| Offset | Size | Field     | Description |
|-------:|-----:|-----------|-------------|
|      0 |    4 | `magic`   | ASCII `"ZEG0"` (`0x3047455A` little-endian, see [`binary_format.hpp`](cpp-guest/include/zeg/binary_format.hpp)) |
|      4 |    4 | `version` | `u32` little-endian format version (`kVersion`, currently `7`). Also keeps the cursor 8-byte aligned for everything that follows |

The guest fatals on magic mismatch or on a `version` other than `kVersion`.
Version `4` made the StateRoot trie hints **witness-only**: the encoder
transcribes the pre-state MPT straight from the execution witness and no
longer pre-emits leaves for keys created during the block — the guest
inserts those into the node array during the new-root pass. The byte layout
is unchanged from v3.
Version `3` removed the standalone Accounts and Storages sections: the
StateRoot section now begins with three `u64` counts and every `Op::Leaf`
carries its key + block-start values, so the guest builds both tables while
walking the trie hints (before it executes the block).
Version `2` folded `NodeR`/`NodeRW` into a single `Branch` opcode and dropped
the `is_read_only` field from the Account (now 128 B) and Storage (now 88 B)
records — the guest derives read-only-ness dynamically (original == current).
Version `1` dropped the per-leaf index from Section 7 (see below).

## Section 1 — `ConsensusInfo`

Per-block consensus-layer inputs for the **current** block (the one
being executed). Schema at
[`consensus_info.hpp`](cpp-guest/include/zeg/consensus_info.hpp).

### Fixed 344-byte header prefix

| Offset | Size | Field                       | Type / encoding         |
|-------:|-----:|-----------------------------|-------------------------|
|      0 |   32 | `parent_hash`               | `bytes32` — in this guest's convention this carries the parent **state root**, not the parent block hash |
|     32 |   20 | `beneficiary`               | 20-byte address         |
|     52 |    4 | pad                         | zero (formerly a u32 `field_count`; the fork is now carried by `fork_id` at offset 336) |
|     56 |    8 | `number`                    | `u64`                   |
|     64 |    8 | `gas_limit`                 | `u64`                   |
|     72 |    8 | `timestamp`                 | `u64`                   |
|     80 |    8 | `extra_data_len`            | `u64`, must be ≤ 32     |
|     88 |   32 | `extra_data`                | byte buffer (only the first `extra_data_len` bytes are meaningful; the rest is zero pad) |
|    120 |   32 | `prev_randao`               | `bytes32`               |
|    152 |   32 | `parent_beacon_block_root`  | `bytes32`               |
|    184 |   32 | `base_fee_per_gas`          | `uint256be` (32-byte big-endian) |
|    216 |    8 | `withdrawals_count`         | `u64`                   |
|    224 |    8 | `excess_blob_gas`           | `u64` (EIP-4844)        |
|    232 |   32 | `requests_hash`             | `bytes32` (EIP-7685; zero pre-Pectra). cpp-guest cross-checks its recomputed value against this and rejects the block on mismatch |
|    264 |   32 | `difficulty`                | `uint256be` — pre-Merge PoW value; `0` post-Merge |
|    296 |    8 | `nonce`                     | 8-byte fixed-width — pre-Merge PoW nonce; `0` post-Merge |
|    304 |   32 | `ommers_hash`               | `bytes32` — `kEmptyOmmersHash` post-Merge |
|    336 |    8 | `fork_id`                   | `u64` — hardfork identity (see [`zeg/fork.hpp`](cpp-guest/include/zeg/fork.hpp)). The guest derives both the EVM revision and the header field count from it. `0` (= Unknown) ⇒ Prague (mainnet default). Distinguishes Osaka from Prague, which share a header layout |
|    344 |      | **end of fixed prefix**     |                         |

`chain_id` is **not** in the stream. It is compile-time pinned to `1`
(Ethereum mainnet) in [`zeg/config.hpp`](cpp-guest/include/zeg/config.hpp).

### Withdrawal records (`withdrawals_count` × 48 bytes)

Immediately follow the prefix. Each record per EIP-4895:

| Offset | Size | Field             | Encoding |
|-------:|-----:|-------------------|----------|
|      0 |    8 | `index`           | `u64`    |
|      8 |    8 | `validator_index` | `u64`    |
|     16 |   20 | `address`         | 20-byte address |
|     36 |    4 | pad               | zero     |
|     40 |    8 | `amount_gwei`     | `u64`    |
|     48 |      | end of record     |          |

## Section 2 — `Transactions`

Every tx of the current block in order. Schema at
[`transactions.hpp`](cpp-guest/include/zeg/transactions.hpp).

| Offset | Size            | Field            | Description |
|-------:|----------------:|------------------|-------------|
|      0 |               8 | `count`          | `u64` — number of transactions |
|      8 | variable        | `tx[0]` … `tx[count-1]` | one record per tx (see below) |

### Per-tx record

Variable-length. Layout for each tx:

```
+--------------------+
| u64  envelope_size |    // 8 B; byte-length of the canonical wire envelope
+--------------------+
| u8   envelope[]    |    // envelope_size bytes — typed: type_byte || rlp(...);
|                    |    // legacy: raw RLP list (no type byte). Type byte is one
|                    |    // of {0x01..0x05} per EIP-2718.
+--------------------+
| u8   pad[0..7]     |    // zero-fill the envelope up to the next 8-byte boundary
+--------------------+
```

No public keys travel in the witness (v6): the guest recovers every
signer — the tx sender and each EIP-7702 authorization signer — from the
signature itself via ecrecover (`secp256k1_ecdsa_recover`, fp_sqrt-fcall
accelerated on ZisK) and derives the address as `keccak256(pubkey)[12:]`.

## Section 3 — `Accounts` *(removed in v3)*

The standalone account table no longer exists. The guest now builds its
[`accounts.hpp`](cpp-guest/include/zeg/accounts.hpp) table from the
StateRoot state-trie leaves: each state `Op::Leaf` carries the account's
address + block-start fields (see [Section 7](#section-7--stateroot-trie-hints)).

## Section 4 — `Contracts`

Deployed bytecode for every code the block executes. Schema at
[`contracts.hpp`](cpp-guest/include/zeg/contracts.hpp).

| Offset | Size      | Field   |
|-------:|----------:|---------|
|      0 |         8 | `count` |
|      8 | variable  | records |

### Contract record (variable)

```
+-------------------+
| u64  code_size    |    // 8 B
+-------------------+
| u8   code[]       |    // code_size bytes of EVM bytecode
+-------------------+
| u8   pad[0..7]    |    // zero-fill to the next 8-byte boundary
+-------------------+
```

The keccak256 of `code` is the lookup key (matching `code_hash` in the
Account record). The guest accesses code zero-copy via the embedded
pointer + length.

## Section 5 — `Storages` *(removed in v3)*

The standalone storage table no longer exists. The guest builds its
[`storages.hpp`](cpp-guest/include/zeg/storages.hpp) table from the
StateRoot storage-trie leaves: each storage `Op::Leaf` carries the slot
position + block-start value (the owning address comes from the enclosing
account leaf — see [Section 7](#section-7--stateroot-trie-hints)).

## Section 6 — `PreviousBlocks`

The current block's parent and earlier ancestors (for EIP-2935 history /
BLOCKHASH). Schema at
[`previous_blocks.hpp`](cpp-guest/include/zeg/previous_blocks.hpp).

| Offset | Size            | Field   |
|-------:|----------------:|---------|
|      0 |               8 | `count` |
|      8 | `count` × 728   | records |

Index 0 = the parent, index `i` = the i-th ancestor. The guest
recomputes each block's hash from canonical Pectra-era header RLP and
verifies the `parent_hash` chain.

### PreviousBlocks record (728 bytes)

All fields are at 8-byte-aligned offsets:

| Offset | Size | Field                       | Encoding |
|-------:|-----:|-----------------------------|----------|
|      0 |   32 | `parent_hash`               | `bytes32` (block hash of the parent) |
|     32 |   32 | `ommers_hash`               | `bytes32` |
|     64 |   20 | `coinbase`                  | address  |
|     84 |    4 | pad                         | zero     |
|     88 |   32 | `state_root`                | `bytes32` |
|    120 |   32 | `transactions_root`         | `bytes32` |
|    152 |   32 | `receipts_root`             | `bytes32` |
|    184 |  256 | `logs_bloom`                | 256-byte Bloom |
|    440 |   32 | `difficulty`                | `uint256be` |
|    472 |    8 | `number`                    | `u64` |
|    480 |    8 | `gas_limit`                 | `u64` |
|    488 |    8 | `gas_used`                  | `u64` |
|    496 |    8 | `timestamp`                 | `u64` |
|    504 |    8 | `extra_data_len`            | `u64`, ≤ 32 |
|    512 |   32 | `extra_data`                | byte buffer (first `extra_data_len` bytes meaningful) |
|    544 |   32 | `prev_randao`               | `bytes32` |
|    576 |    8 | `nonce`                     | 8 raw bytes (Ethereum encodes header `nonce` as a fixed-width bytestring, not a trimmed integer) |
|    584 |   32 | `base_fee_per_gas`          | `uint256be` |
|    616 |   32 | `withdrawals_root`          | `bytes32` |
|    648 |    8 | `blob_gas_used`             | `u64` |
|    656 |    8 | `excess_blob_gas`           | `u64` |
|    664 |   32 | `parent_beacon_block_root`  | `bytes32` |
|    696 |   32 | `requests_hash`             | `bytes32` |
|    728 |      | end of record               |          |

## Section 7 — `StateRoot` trie hints

Trie-walk hints used by [`state_root.cpp`](cpp-guest/src/state_root.cpp)
to recompute the world-state trie root in two passes (pre-execution
against original values, post-execution against modified values). As of
version `3` this section is also where the guest builds its Accounts and
Storages tables — one row per keyed leaf.

### Header (3 × `u64`)

| Offset | Field              | Description |
|-------:|--------------------|-------------|
|      0 | `numberOfNodes`    | Node count. Up to v8 the encoder emitted `stream_len / 8`, sound because every node cost at least one 8-byte opcode word; a v9 tagged `Empty` child costs zero bytes, so the encoder now counts nodes explicitly. The guest uses it as a cache-overflow ceiling, so any value ≥ the true count is safe. |
|      8 | `numberOfAccounts` | Exact number of state-trie leaves = Accounts table size. Pre-sizes the table. |
|     16 | `numberOfStorages` | Exact number of storage-trie leaves = Storages table size. Pre-sizes the table. |

The opcode stream follows the header. The format is an opcode-tagged
depth-first walk. Each opcode is a `u64` (so consumed reads stay 8-byte
aligned), followed by an opcode-specific payload:

| Opcode (u64) | Name            | Payload |
|-------------:|-----------------|---------|
|            0 | `Empty`         | — (zero payload) |
|            1 | `Hash`          | 32 B `bytes32` (a subtree's already-known root hash). Stands in for an UNTOUCHED subtree only — one with no table rows under it — so it appends no rows and leaves the guest's leaf counters unchanged. |
|            2 | `ExtensionHash` | `u64 nibbles_count` + the nibbles packed **two per byte** (high nibble first), zero-padded to the next 8-byte boundary + 32 B `bytes32` |
|            3 | `Leaf`          | **v7 (hybrid: suffix nibbles + plaintext key):** the leaf's own remaining path nibbles AND its plaintext key AND block-start values. Payload begins with `suffix_len` (`u64`) then the suffix nibbles packed **two per byte** (high nibble first), zero-padded to the next 8-byte boundary; the guest reconstructs the 32-byte trie key hash as `keccak(addr)`/`keccak(slot)` = `pack(walked_prefix ++ suffix)` (must total 64 nibbles) with NO preimage — so it stays stateless. The plaintext key then follows so the guest can key its runtime tables by plaintext (fast hot path), and the guest asserts `keccak(plaintext) == pack(walked ++ suffix)`. **State leaf**: suffix-prefix, then `address` (20 B) + 4 B zero pad, then `balance` (`uint256be`, 32 B) + `nonce` (`u64`) + `code_hash` (32 B); then the nested storage subtree follows as a recursive node. **Storage leaf** (under a state leaf's subtree): suffix-prefix, then `position` (32 B) + `value` (32 B) (the owning address comes from the enclosing account leaf). The guest appends one Accounts/Storages row per leaf, keyed by plaintext, indexed by trie-walk order. Leaves whose preimage is missing from `witness.keys` are emitted as `PhantomLeaf` instead. |
|            4 | `Branch`        | `u64 child_tags` + the children's payloads in nibble order. `child_tags` holds **two bits per child** at bit `2k`: `0` = `Empty`, `1` = `Hash`, `2` = a full node. A tagged `Empty` child contributes **no bytes at all** and a tagged `Hash` child only its 32, because neither carries an opcode word — a tag `2` child is a complete node, opcode included. Children reached outside a branch (the trie root, and each account leaf's storage subtree) still carry their own opcode word. |
|            5 | `PhantomLeaf`   | `u64 nibbles_count` + the remaining path nibbles packed **two per byte** (high nibble first, zero-padded to 8 B) + `u64 value_len` + `value_len` bytes + zero pad to the next 8-byte boundary. A keyless sibling leaf (its preimage is missing from `witness.keys`), so it gets no table row — it contributes its hash but is never indexed. **Pre-funded exception:** a keyless *state* phantom with a non-zero balance is a CREATE2 target funded in a prior block; the guest records `keccak(addr) → balance` so that if the block CREATEs a contract there, `ensure_account` seeds the new row from that balance (Yellow Paper: CREATE preserves any pre-existing balance) and the new-root pass supersedes the stale phantom leaf. |

The walk consumes exactly as many bytes as the trie requires; the
trailing byte of the last payload is also the last byte of the file
(modulo final alignment pad).

The guest assigns each leaf the next index from a running per-type
counter, which is also the position at which it `append`s the row. The
two passes differ:

* **Pre-execution (old-root) pass** — runs **before** the block executes.
  Walks every node against the block-start values, appending one
  Accounts/Storages row per keyed leaf and checking that each leaf's
  `keccak256(key)` matches its walked path (this binds the payload key to
  its trie position). The resulting old root is matched against the
  trusted parent anchor by the caller; a missing or misplaced row makes
  that match fail, so a complete, correctly-placed witness is required.
* **Post-execution (new-root) pass** — re-walks against the post-block
  values to recompute the root, and **inserts keys created during the
  block**. As of v4 the encoder is witness-only and does not pre-emit
  leaves for created keys; the guest navigates `keccak256(key)` in the node
  array and places the leaf at an `Empty` slot or splits a colliding sibling
  into a fresh branch. Deletion is not structural — a zeroed account/slot
  becomes empty and the branch folds. (A child referencing the empty-trie
  root is emitted as `Op::Empty`, so a first write into empty storage is an
  insert, not a fatal.)

Read-only-ness is **derived dynamically**, not declared on the wire:
a leaf is read-only iff its original value equals its current value; a
`Branch`/`ExtensionHash` is read-only iff all its children are. The
old-root pass records every node's computed result in a per-node array (in
post-order); the new-root pass walks the same array and, for a read-only
node, reuses the cached result instead of re-hashing.

## Encoding conventions cheat-sheet

| Type / field     | Wire form |
|------------------|-----------|
| `u32` / `u64`    | Little-endian, native width |
| `address`        | 20 raw bytes, followed by 4 B zero pad whenever a struct holds it (to keep the next field 8-aligned) |
| `bytes32`        | 32 raw bytes (Ethereum canonical) |
| `uint256be`      | 32 raw big-endian bytes (Ethereum canonical) |
| `bool`-as-`u64`  | `0` = false, `1` = true |
| Variable buffers | `u64` length prefix, then bytes, then zero pad to the next 8-byte boundary |

## Source of truth

Every offset and record size in this document is mirrored as
`constexpr` `kFieldOffset` / `kRecordSize` constants in the
corresponding header under
[`cpp-guest/include/zeg/`](cpp-guest/include/zeg/). When the layout
changes, update both this document and the header in the same change.
