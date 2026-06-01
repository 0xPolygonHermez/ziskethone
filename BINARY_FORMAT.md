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
|  Accounts                 |
+---------------------------+
|  Contracts                |
+---------------------------+
|  Storages                 |
+---------------------------+
|  PreviousBlocks           |
+---------------------------+
|  StateRoot trie hints     |
+---------------------------+
```

No padding between sections — each section's last record is itself
sized to a multiple of 8, so the next section starts 8-byte aligned.

## Section 0 — Magic prefix (8 bytes)

| Offset | Size | Field     | Description |
|-------:|-----:|-----------|-------------|
|      0 |    4 | `magic`   | ASCII `"ZEG0"` (`0x3047455A` little-endian, see [`binary_format.hpp`](cpp-guest/include/zeg/binary_format.hpp)) |
|      4 |    4 | `version` | `u32` little-endian format version (`kVersion`, currently `1`). Also keeps the cursor 8-byte aligned for everything that follows |

The guest fatals on magic mismatch or on a `version` other than `kVersion`.
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
| u8   pubkey[64]    |    // 64 B uncompressed sender secp256k1 pubkey (x || y, BE)
+--------------------+
| u8   envelope[]    |    // envelope_size bytes — typed: type_byte || rlp(...);
|                    |    // legacy: raw RLP list (no type byte). Type byte is one
|                    |    // of {0x01..0x05} per EIP-2718.
+--------------------+
| u8   pad[0..7]     |    // zero-fill the envelope up to the next 8-byte boundary
+--------------------+
| u8   auth_pk[]     |    // ONLY for Type-4 (SetCode / EIP-7702): N × 64 B
|                    |    // uncompressed pubkeys, one per authorization in the
|                    |    // tx's authorization_list. 64 B is already 8-aligned.
+--------------------+
```

The prover supplies the sender pubkey alongside each envelope so the
guest can verify the signature without running secp256k1 recovery; the
signer address is then derived as `keccak256(pubkey)[12:]`. Same
mechanism for each EIP-7702 auth signer.

## Section 3 — `Accounts`

State-trie account table for every account the block touches. Schema at
[`accounts.hpp`](cpp-guest/include/zeg/accounts.hpp).

| Offset | Size                          | Field      |
|-------:|------------------------------:|------------|
|      0 |                             8 | `count`    |
|      8 | `count` × 136                 | records    |

### Account record (136 bytes)

| Offset | Size | Field         | Encoding |
|-------:|-----:|---------------|----------|
|      0 |   20 | `address`     | 20-byte address |
|     20 |    4 | pad           | zero |
|     24 |   32 | `balance`     | `uint256be` |
|     56 |    8 | `nonce`       | `u64` |
|     64 |   32 | `storage_root`| `bytes32` (root of the account's storage trie at block start) |
|     96 |   32 | `code_hash`   | `bytes32` (keccak256 of the deployed code; `keccak256("")` for EOAs) |
|    128 |    8 | `is_read_only`| `u64` — `1` if the prover marked this account read-only for this block, `0` otherwise |
|    136 |      | end of record |          |

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

## Section 5 — `Storages`

Per-account storage slots the block touches. Schema at
[`storages.hpp`](cpp-guest/include/zeg/storages.hpp).

| Offset | Size           | Field   |
|-------:|---------------:|---------|
|      0 |              8 | `count` |
|      8 |  `count` × 96  | records |

### Storage record (96 bytes)

| Offset | Size | Field         | Encoding |
|-------:|-----:|---------------|----------|
|      0 |   20 | `address`     | 20-byte address |
|     20 |    4 | pad           | zero |
|     24 |   32 | `position`    | `bytes32` (storage slot key) |
|     56 |   32 | `value`       | `bytes32` (slot value at block start) |
|     88 |    8 | `is_read_only`| `u64` — `1` if the prover marked this slot read-only, `0` otherwise |
|     96 |      | end of record |          |

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
against original values, post-execution against modified values).

The format is an opcode-tagged depth-first walk. Each opcode is a
`u64` (so consumed reads stay 8-byte aligned), followed by an
opcode-specific payload:

| Opcode (u64) | Name            | Payload |
|-------------:|-----------------|---------|
|            0 | `Empty`         | — (zero payload) |
|            1 | `Hash`          | 32 B `bytes32` (a subtree's already-known root hash). Stands in for an UNTOUCHED subtree only — one with no Accounts/Storages table rows under it — so it skips no leaves and leaves the guest's leaf counters unchanged. |
|            2 | `ExtensionHash` | `u64 nibbles_count` + `nibbles_count` × `u64` (one nibble per `u64`, low 4 bits used) + 32 B `bytes32` |
|            3 | `Leaf`          | — (no payload). The Accounts/Storages tables are sorted in trie-walk order (by `keccak256(address)` and `(keccak256(address), keccak256(slot))`), so the guest assigns each leaf the next index from a running per-type counter rather than reading it. Leaves walked under a state-trie `NodeRW` may contain a nested storage subtree via a recursive `walk_node` call |
|            4 | `NodeRW`        | 16 sub-trees (one per branch nibble), each itself a recursive node |
|            5 | `NodeR`         | Same shape as `NodeRW` but marks the subtree read-only — every contained leaf must reference an `is_read_only == true` entry in `Accounts` / `Storages`. The result of a `NodeR` subtree is cached during the old-root pass and reused unchanged in the new-root pass. |

The walk consumes exactly as many bytes as the trie requires; the
guest does not pre-declare a total stream size — the trailing byte of
the last payload is also the last byte of the file (modulo final
alignment pad).

Because `Leaf` carries no index, the guest derives it from running state
and storage counters. The two passes differ:

* **Pre-execution (old-root) pass** — walks every node against the
  block-start values. Each `Leaf` takes the next counter value, and the
  guest checks that the indexed Accounts/Storages key's hash matches the
  walked path (`Leaf`s are thus accessed consecutively, keys must match).
  Every leaf under a `NodeR` must reference a read-only row. At the end,
  each counter must equal its table length exactly — so every row appears
  as exactly one leaf, none repeated or missing. An `Op::Hash` stands in
  only for untouched (0-row) subtrees; if reth's witness is missing a node
  over read-only rows, those rows have no leaf and this check rejects the
  block (a complete witness is required — strict).
* **Post-execution (new-root) pass** — re-walks against the post-block
  values to recompute the root, skipping the key and count checks. Before
  it runs, the guest verifies every read-only Accounts/Storages row is
  unchanged.

To avoid re-walking unchanged read-only regions, the old-root pass caches
each `NodeR` found directly under a `NodeRW`: it records the node's walk
result, the cursor advance, and the state/storage leaf indices reached
**after** the subtree. The new-root pass replays the cache — advancing the
cursor and **setting** the leaf counters to those recorded indices —
instead of walking the subtree again.

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
