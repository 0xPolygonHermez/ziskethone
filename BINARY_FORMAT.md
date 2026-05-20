# Binary Input Format (v0)

This document defines the on-disk binary format produced by `rust-input-gen` and
consumed by the ZisK C++ guest program (`cpp-guest`).

## Design goals

- **Zero-copy / zero-parse on the guest side.** The C++ guest should be able
  to `mmap` (or read into a buffer) the file and access fields directly via
  pointer casts to packed C structs.
- **Fixed endianness:** all multi-byte integers are stored **little-endian**
  (matches RISC-V / x86 and ZisK's target).
- **Byte-packed structs** (no implicit padding). Use `#pragma pack(1)` /
  `__attribute__((packed))` on the C++ side and `#[repr(C, packed)]` on the
  Rust side.
- **Length-prefixed variable sections** so the guest can iterate without
  external metadata.
- **Section offset table at the start** for O(1) random access.

## Top-level layout

```
+------------------------+  offset 0
|  FileHeader            |
+------------------------+
|  SectionTable[N]       |
+------------------------+
|  Section 0 payload     |
+------------------------+
|  Section 1 payload     |
+------------------------+
|  ...                   |
+------------------------+
```

### `FileHeader` (32 bytes)

| Offset | Size | Field            | Description                              |
|-------:|-----:|------------------|------------------------------------------|
|      0 |    4 | `magic`          | ASCII `"ZEB0"` (Zisk Eth Block, v0)      |
|      4 |    4 | `version`        | `u32` — format version (currently `0`)   |
|      8 |    4 | `section_count`  | `u32` — number of entries in table       |
|     12 |    4 | `flags`          | `u32` — reserved, must be `0`            |
|     16 |    8 | `chain_id`       | `u64` — EVM chain id                     |
|     24 |    8 | `block_number`   | `u64` — block being verified             |

### `SectionEntry` (16 bytes each)

| Offset | Size | Field      | Description                                    |
|-------:|-----:|------------|------------------------------------------------|
|      0 |    4 | `kind`     | `u32` — section kind tag (see below)           |
|      4 |    4 | `reserved` | `u32` — must be `0`                            |
|      8 |    4 | `offset`   | `u32` — byte offset from start of file         |
|     12 |    4 | `length`   | `u32` — payload length in bytes                |

### Section kinds (v0)

| Kind | Name                  | Payload                                            |
|-----:|-----------------------|----------------------------------------------------|
|    1 | `PARENT_HEADER`       | One RLP-encoded block header (parent of target)    |
|    2 | `CURRENT_HEADER`      | One RLP-encoded block header (target block)        |
|    3 | `TRANSACTIONS`        | Length-prefixed list of RLP-encoded transactions   |
|    4 | `WITHDRAWALS`         | Length-prefixed list of RLP-encoded withdrawals    |
|    5 | `STATE_TRIE_NODES`    | Length-prefixed list of MPT node blobs             |
|    6 | `STORAGE_TRIE_NODES`  | Length-prefixed list of MPT node blobs             |
|    7 | `BYTECODES`           | Length-prefixed list of contract bytecodes         |
|    8 | `ANCESTOR_HEADERS`    | Length-prefixed list of RLP-encoded headers (≤256) |

Unknown kinds **must** be ignored by readers for forward compatibility.

### Length-prefixed list payload

```
+----------------+----+----------------+-----+-----+----------------+-----+
| u32 item_count | u32 len_0 | bytes_0 | u32 len_1 | bytes_1 | ... |
+----------------+----+----------------+-----+-----+----------------+-----+
```

All lengths are `u32` little-endian. Items are stored back-to-back with no
padding.

## Rationale: RLP payloads vs. parsed structs

For v0 we keep RLP-encoded blobs rather than fully parsed C structs because:

1. Ethereum block hashing is defined over the RLP encoding — the guest needs
   the exact bytes anyway to compute Keccak-256.
2. It keeps the binary format stable across Ethereum hard forks (new header
   fields don't break layout).

The C++ guest performs RLP decoding internally; only the *envelope* (sections,
offsets, lengths) needs to be zero-parse.

## Versioning

- The `version` field in `FileHeader` is bumped on any breaking change.
- New section kinds may be added without bumping `version` as long as readers
  ignore unknown kinds.
