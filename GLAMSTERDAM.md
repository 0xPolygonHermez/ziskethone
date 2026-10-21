# Glamsterdam (Amsterdam) — implementation tracker

Glamsterdam is the Ethereum upgrade after Fusaka; **Amsterdam** is its
execution-layer half (the consensus half is Gloas). It activated on Sepolia on
2026-10-06; mainnet is not scheduled yet.

Status on branch `glamsterdam`: the test pipeline and the guest groundwork are
in place, and the EIPs are being implemented one by one (Status column below).

- `eest-witness-gen` is on **reth v2.7.0** (the first release with Amsterdam on
  Sepolia). It maps the `Amsterdam` and `…ToAmsterdamAtTime…` networks, with blob
  parameters from the fixture's `blobSchedule`. It also writes the new header
  fields (`blockAccessListHash`, `slotNumber`) into the manifest.
- `input-gen` emits `fork_id = 8` (Amsterdam) for any header that carries
  `block_access_list_hash`. The binary format is v12 (see `BINARY_FORMAT.md`):
  - ConsensusInfo carries `slot_number`;
  - the BAL hash is not an input, because the guest computes it;
  - every key the block loads is a StateRoot leaf (an empty one if it doesn't
    exist), and sorted-order links over the rows give the BAL's order.
- The guest accepts Amsterdam: `ForkId::Amsterdam` → `EVMC_AMSTERDAM`, the
  23-field header for the current block and its ancestors, SLOTNUM's
  `block_slot_number` in the tx context, and `is_amsterdam_or_later()`.
- The guest is on **evmone v0.24.0** (EVMC ABI 19, Amsterdam revision). zevm is
  ported to the same ABI and has an `EVMC_AMSTERDAM` dispatch loop: the Osaka
  opcode set plus SLOTNUM and DUPN / SWAPN / EXCHANGE.

## Fixtures

Source: [`tests@v21.0.1`](https://github.com/ethereum/execution-specs/releases/tag/tests%40v21.0.1)
(2026-10-08), the first mainnet release that includes Amsterdam. Fixtures are
now grouped by the fork they are filled for (`for_<fork>/`):

```bash
mkdir -p /tmp/eest-v21 && cd /tmp/eest-v21
gh release download tests@v21.0.1 -R ethereum/execution-specs -p fixtures.tar.gz
tar xzf fixtures.tar.gz
# → /tmp/eest-v21/fixtures/blockchain_tests/for_amsterdam/...
#   /tmp/eest-v21/fixtures/blockchain_tests/for_bpo2toamsterdamattime15k/...
```

`for_amsterdam/amsterdam/` holds the per-EIP tests. The other directories under
`for_amsterdam/` re-run earlier forks' tests (and `ported_static`) under
Amsterdam rules, so they catch regressions from the repricing EIPs.

## Running

```bash
F=/tmp/eest-v21/fixtures/blockchain_tests
# one EIP
scripts/eest_sweep.sh $F/for_amsterdam/amsterdam/eip7843_slotnum
# the whole fork, plus the fork transition
scripts/eest_sweep.sh $F/for_amsterdam $F/for_bpo2toamsterdamattime15k
# with the zevm backend
scripts/eest_sweep.sh -g cpp-guest/build-zevm/zisk_eth_guest $F/for_amsterdam/amsterdam
```

## EIPs

The 15 Amsterdam EL EIPs, per the
[execution-specs test tracker](https://github.com/ethereum/execution-specs/issues/3217).
Fixture counts are from `for_amsterdam/amsterdam/<dir>`.

| EIP | Title | Fixture dir | Fixtures / blocks | Status |
|---|---|---|---|---|
| [2780](https://eips.ethereum.org/EIPS/eip-2780) | Resource-based intrinsic tx gas | `eip2780_reduce_intrinsic_tx_gas` | 61 / 283 | done |
| [7708](https://eips.ethereum.org/EIPS/eip-7708) | ETH transfers emit a log | `eip7708_eth_transfer_logs` | 40 / 77 | done |
| [7778](https://eips.ethereum.org/EIPS/eip-7778) | Block gas accounting without refunds | `eip7778_block_gas_accounting_without_refunds` | 9 / 117 | done (rule landed with 8037) |
| [7843](https://eips.ethereum.org/EIPS/eip-7843) | SLOTNUM opcode (+ `slot_number` header field) | `eip7843_slotnum` | 10 / 23 | done |
| [7928](https://eips.ethereum.org/EIPS/eip-7928) | Block-level access lists (+ `block_access_list_hash` header field) | `eip7928_block_level_access_lists` | 211 / 1,248 | done |
| [7954](https://eips.ethereum.org/EIPS/eip-7954) | Increase max contract size | `eip7954_increase_max_contract_size` | 22 / 58 | done |
| [7976](https://eips.ethereum.org/EIPS/eip-7976) | Increase calldata floor cost | `eip7976_increase_calldata_floor_cost` | 21 / 543 | done |
| [7981](https://eips.ethereum.org/EIPS/eip-7981) | Increase access list cost | `eip7981_increase_access_list_cost` | 19 / 189 | done |
| [7997](https://eips.ethereum.org/EIPS/eip-7997) | Deterministic factory contract | `eip7997_deterministic_factory_contract` | 21 / 40 | done (no guest change) |
| [8024](https://eips.ethereum.org/EIPS/eip-8024) | DUPN / SWAPN / EXCHANGE | `eip8024_dupn_swapn_exchange` | 66 / 288 | done |
| [8037](https://eips.ethereum.org/EIPS/eip-8037) | State creation gas cost increase (state-gas reservoir) | `eip8037_state_creation_gas_cost_increase` | 270 / 834 | done |
| [8038](https://eips.ethereum.org/EIPS/eip-8038) | State access gas cost increase | `eip8038_state_access_gas_cost_increase` | 88 / 263 | done |
| [8070](https://eips.ethereum.org/EIPS/eip-8070) | eth/72 sparse blobpool | — | — | n/a (networking only) |
| [8246](https://eips.ethereum.org/EIPS/eip-8246) | Remove SELFDESTRUCT burn | `eip8246_selfdestruct_no_burn` | 9 / 663 | done |
| [8282](https://eips.ethereum.org/EIPS/eip-8282) | Builder execution requests | `eip8282_builder_execution_requests` | 22 / 356 | done |

### Open items that span EIPs

- **EIP-8025 public output.** The guest's public output is now the
  `new_payload_request_root`: the SSZ `hash_tree_root` (progressive containers,
  EIP-7916/7495) of the block's Engine API `NewPayloadRequest`. The host guest
  prints the block hash first and the root on the last line. The guest still
  reads ZEG0 input (not the EIP's `StatelessInput`) and halts on an invalid
  block, so it emits only the root, not the full `StatelessValidationResult`.
  The Amsterdam schema is used for every fork (an empty BAL and slot 0 before
  Amsterdam). `scripts/npr_root_ref.py` recomputes the root with execution-specs
  @3ebcb5d; `cpp-guest/test/ssz_test.cpp` holds the merkleization vectors.
  `partial_request_records` (12 blocks) have no root: see `NA_POS` in the README.

- **EIP-7997 needs no guest code.** The fixtures inject nothing at the fork:
  `factory_untouched_across_transition` keeps a chain without the factory
  without it. Every other test has the factory (0x4e59…956c) in its pre-state,
  as mainnet has since 2019. Both backends pass all 40 blocks and the 19
  transition blocks.

- **BAL loads follow the VM's host calls.** An account counts as loaded when
  the guest reads or writes it. A bare `access_account` counts once the VM
  shows it paid the access cost: by making another host call in the frame, or
  by the frame ending normally. That reproduces revm skipping a cold load it
  can't pay for. zevm follows the same host-call pattern as evmone.
- **BAL order comes from the witness.** There is no BAL input: every key the
  block loads is a leaf, and the StateRoot rows carry sorted-order links (see
  "Every loaded key is a leaf" below). Online `input-gen` needs the node's
  prestate tracer on top of the witness, because reth's `witness.keys` omits
  accounts that were loaded but don't exist (`docs/reth-witness-absent-keys.patch`
  fixes that in reth).
- **The gas EIPs are entangled.** Most fixtures of one gas EIP also exercise
  the others, so 2780, 7708, 7778, 7976, 7981 and 8037 were only measurable
  together. 8037's block accounting is EIP-7778's rule (no refund in the
  block's gas). 7981's access-list item price includes 8038's
  `COLD_* − WARM_ACCESS` (2,900 / 2,000).
- **evmone v0.24 already has the in-VM parts** of 8038 (access costs), 7843
  (SLOTNUM) and 8024 (DUPN / SWAPN / EXCHANGE) for `EVMC_AMSTERDAM`. All of them
  are now in zevm too.
- **EIP-2780's "authority existed"** test is EIP-161 non-empty
  (`account_exists`). revm also counts an empty account that is in the trie;
  such an account can't arise on mainnet after Spurious Dragon.
- **Total tx gas cap.** `TX_MAX_TOTAL_GAS_LIMIT` (2^32 − 1) comes from
  execution-specs and the fixtures; revm 43 and reth 2.7 don't implement it.
- **System calls** get 30M regular gas plus a 16-slot state-gas reservoir, as
  evmone and the fixtures do. revm 43 gives 30M + 16 × 97,920 regular gas
  instead.
- **zevm** has every Amsterdam EIP: the 8037 state gas, the 8038 access costs,
  and the 8024 and 7843 opcodes. It matches evmone on all Amsterdam fixtures.
- **Proving cost.** On a mainnet block (26167511) the evmone ELF takes +3.3%
  steps on evmone v0.24 vs v0.21 (136.0M → 140.5M); zevm is unchanged.

## Baseline

### Before the guest groundwork

Branch `glamsterdam`, `tests@v21.0.1`, evmone guest, 2026-10-11:

| Fixture set | Fixtures | Blocks | Result |
|---|---|---|---|
| `for_amsterdam/amsterdam` (the 14 EIP dirs) | 869 | 4,982 | 4,982 `FAIL(unsupported_fork)` |
| rest of `for_amsterdam` + `for_bpo2toamsterdamattime15k` | 2,485 | 28,171 | 27,962 `FAIL(unsupported_fork)`, 162 PASS + 15 PASS_NEG, 32 MISSING |

- **PASS / PASS_NEG:** all 177 are the pre-fork (BPO2) blocks of the transition
  fixtures.
- **MISSING:** all 32 are invalid blocks that reth can't decode, the same
  category as on earlier forks: bad signatures, contract-creating blob/7702
  transactions, and headers with the wrong Amsterdam field set.
- **Bridge:** no fixture failed in the bridge.

The reth 2.2 → 2.7 bridge upgrade was regression-checked on the
`tests-v5.4.0` Prague + Osaka corpus: 3,820 PASS, 274 PASS_NEG, 0 FAIL, 1 MISSING
(the undecodable `test_contract_create` type-4 creation).

### Every loaded key is a leaf (format v12)

The BAL order no longer comes from a hint, and the witness proves every key
the block reads.

- **Before:** the guest made up an empty row for any address it couldn't find
  (`ensure_account`), and read 0 for any missing slot (`DynamicStorage`). A key
  that was only read, never written, was never checked: a prover could hide an
  existing account or slot behind an `Op::Hash` subtree.
- **Now:** every account and slot the block loads is a StateRoot leaf. A key
  that doesn't exist is an empty-valued leaf placed where it would sit; it
  hashes as `Empty`, so the parent-root check proves the absence. A load of
  any other key halts ("state key not in witness"). Warming (EIP-2929 / 2930)
  isn't a load and is tracked by plaintext (`WarmKeys`). No row is appended at
  run time; `DynamicStorage`, phantom-account seeding and the new-root insert
  pass are gone.
- **An account leaf with empty fields is absent only if its storage root is
  empty too.** Otherwise a prover could hang slots under an absent account
  unseen by the root. Such an account is now hashed as a real leaf.
- **BAL order:** each row carries a sorted-order link (accounts by address,
  each account's slots by position). At the end of an Amsterdam block the guest
  walks them, checking strict order, ownership and that every row is visited,
  and encodes the accessed ones. The BalHint section is gone.
- **Where the keys come from:**
  - online `input-gen`: reth's `witness.keys` (an address followed by its
    slots) plus the prestate tracer, because reth drops loaded accounts that
    don't exist (3–5 per mainnet block; `docs/reth-witness-absent-keys.patch`
    fixes that in reth);
  - `eest-witness-gen`: its touched sets plus a per-tx state hook, which still
    has the slots of an account created and self-destructed in the same tx
    (the cache and the bundle drop them).

**Results** (both backends unless noted):

| Set | Result |
|---|---|
| `for_amsterdam/amsterdam` | 4,982 / 4,982 (7928: 1,248 / 1,248 with no hint) |
| rest of `for_amsterdam` | identical block for block (22,523 PASS, 5,215 PASS_NEG) |
| fork transition | 366 PASS, 35 PASS_NEG, 0 FAIL |
| tests-v5.4.0 + InvalidBlocks | identical except 2 NA_NEG → PASS_NEG |
| mainnet, 7 blocks at head-3 | correct hash, host builds; ELFs on one block |

- The 2 NA_NEG → PASS_NEG are `shanghaiWithoutWithdrawalsRLP`: an undecodable
  block, so the generator has no keys for it and the guest halts on the
  withdrawal recipient. That rejection is no evidence of an RLP check.
- **Negative tests (mainnet, scratch encoder):** leaving out an accessed absent
  account halts; presenting an existing account as empty, or hanging a
  non-zero slot under an absent account, fails the old root.
- **Proving cost** (block 26182405, same block, v11 → v12): zevm ELF
  66,774,341 → 66,787,855 steps (+0.02%), evmone ELF 59,138,994 → 59,131,144
  (−0.01%). The input grows 1% (6.58 → 6.65 MB): mainnet blocks carry 7–50
  absent accounts and 137–803 absent slots.
- **Sepolia:** `ZEG_CHAIN=sepolia` builds (chain id 11155111, deposit contract
  0x7f02…295d; the system contracts match `eth_config`), and `input-gen`
  picks the fork schedule by chain id. On a local Sepolia reth node
  (v2.7.0), 11 consecutive Amsterdam blocks (11906720–11906730, 114–227 txs,
  57–98 Mgas) give the real block hash on both host builds; blocks carry
  3–23 absent accounts and 96–392 absent slots. Blocks 11906724 and
  11906727 also match on both GCC 14 ZisK ELFs under ziskemu: 568,839,327 /
  397,443,082 steps (zevm) and 494,834,076 / 347,189,983 (evmone).

### After EIP-7843

zevm gets SLOTNUM (0x4b) in its Amsterdam dispatch loop. It costs 2 gas and
pushes `tx_context.block_slot_number`. The host already fills that field from
ConsensusInfo's `slot_number` (the groundwork), so there is no host change.

**zevm now matches evmone on every Amsterdam fixture:**

| Set | evmone | zevm |
|---|---:|---:|
| `for_amsterdam/amsterdam` (14 EIP dirs) | 4,982 / 4,982 | 4,982 / 4,982 |
| rest of `for_amsterdam` | 22,523 PASS, 5,215 PASS_NEG, 0 FAIL | identical block for block |
| fork transition | 366 PASS, 35 PASS_NEG, 0 FAIL | identical |

FAIL_NEG is 0 everywhere.
- **Prague + Osaka on zevm:** identical block for block (3,820 / 274 / 1).
- **ELF:** the zevm ELF (GCC 14) matches the host on 23/23 7843 blocks.
- **Proving cost:** on mainnet the zevm ELF takes +0.42% steps on block
  26176606 (94.22M → 94.61M) and +0.21% on block 26177276 (27.39M → 27.45M).
  The pre-Amsterdam loops run the same source; the new `case 0x4b` label (which
  behaves like `default:` before Amsterdam) changes GCC's block layout in every
  fork's loop.

### After EIP-8024

zevm gets DUPN (0xe6), SWAPN (0xe7) and EXCHANGE (0xe8) in its Amsterdam
dispatch loop, ported from evmone v0.24:
- **Cost and pc:** each costs 3 gas and advances pc by 2.
- **Immediate:** a one-byte immediate past the end of code reads as 0.
- **Forbidden immediates** (0x5b–0x7f; 0x52–0x7f for EXCHANGE) are an
  undefined instruction. Because of them an immediate is never JUMPDEST or a
  PUSH opcode, so JUMPDEST analysis doesn't change.

There is no host change; evmone already had the opcodes.

| Set | zevm before | zevm after |
|---|---:|---:|
| `for_amsterdam/amsterdam`, 8024 | 190 / 288 | 288 / 288 |
| `for_amsterdam/amsterdam`, all | 4,863 / 4,982 | 4,961 / 4,982 |
| rest of `for_amsterdam`, FAIL | 13 | 4 |
| fork transition, FAIL | 8 | 2 |

All of zevm's remaining failures are SLOTNUM (7843): 21 of its 23 blocks, the 4
opcode-enumeration blocks and the 2 transition blocks. FAIL_NEG stays 0.
- **Prague + Osaka on zevm:** identical block for block (3,820 / 274 / 1).
- **ELF:** the zevm ELF (GCC 14) matches the host on 288/288 8024 blocks.
- **Mainnet block 26176606:** the zevm ELF takes 94.22M steps, unchanged.

### After EIP-8038

The host parts of 8038 landed with 2780, 7981 and 8037: the intrinsic
access-list and create costs, the top-frame 7702 delegation charge, and the
authorization `ACCOUNT_WRITE`. evmone v0.24 has the in-VM part. This step ports
the in-VM part to zevm, matching evmone v0.24's Amsterdam costs:

| Cost | Osaka | Amsterdam |
|---|---:|---:|
| Cold account access (SELFDESTRUCT, 7702 delegate) | 2,600 | 3,000 |
| Cold surcharge over the warm base (BALANCE, EXT*, CALL*) | 2,500 | 2,900 |
| EXTCODESIZE / EXTCODECOPY base | 100 | 200 |
| CREATE / CREATE2 base | 32,000 | 12,000 |
| CALL / CALLCODE value cost (stipend still given back) | 9,000 | 11,300 |
| SSTORE set / reset | 20,000 / 2,900 | 10,100 / 10,100 |
| SSTORE clear refund | 4,800 | 11,616 |
| SSTORE cold surcharge | 2,100 | 2,000 |

zevm's CALL now runs its checks in evmone's order on every fork: static value,
then memory, value cost, target access, 7702 delegate and new account.
- **Gas:** the order doesn't change it, because each early exit is an
  exceptional halt that burns all gas.
- **BAL:** the order does decide which accounts the host sees loaded before
  the halt, and from Amsterdam that set is the BAL.

| EIP | Blocks | evmone pass | zevm pass | FAIL_NEG (zevm) |
|---|---:|---:|---:|---:|
| 2780 | 283 | 283 | 283 | 0 |
| 7708 | 77 | 77 | 77 | 0 |
| 7778 | 117 | 117 | 117 | 0 |
| 7843 | 23 | 23 | 2 | 0 |
| 7928 | 1,248 | 1,248 | 1,248 | 0 |
| 7954 | 58 | 58 | 58 | 0 |
| 7976 | 543 | 543 | 543 | 0 |
| 7981 | 189 | 189 | 189 | 0 |
| 7997 | 40 | 40 | 40 | 0 |
| 8024 | 288 | 288 | 190 | 0 |
| 8037 | 834 | 834 | 834 | 0 |
| 8038 | 263 | 263 | 263 | 0 |
| 8246 | 663 | 663 | 663 | 0 |
| 8282 | 356 | 356 | 356 | 0 |
| **total** | **4,982** | **4,982** | **4,863** | **0** |

zevm now fails only blocks that use the 8024 / 7843 opcodes.
- **Rest of `for_amsterdam`** (earlier forks' tests under Amsterdam rules,
  27,745 blocks): zevm 22,510 PASS, 5,215 PASS_NEG, 13 FAIL; evmone 22,523 /
  5,215 / 0. The 13 are the DUPN / SWAPN / EXCHANGE / SLOTNUM cases of the
  opcode-enumeration tests.
- **Fork transition:** zevm 358 PASS, 35 PASS_NEG, 8 FAIL. All 8 are 8024 / 7843
  opcode-at-fork blocks.
- **Regression:** the full tests-v5.4.0 + InvalidBlocks corpus on zevm is
  identical block for block before and after the change.
- **Proving cost:** the zevm ELF on mainnet block 26176606 takes 94.22M steps,
  against 94.19M before (+0.03%).

### After EIP-7928

The guest builds the block-level access list while it executes and puts its
hash into the header. The input no longer carries the hash.

- **Accessed set.** An `accessed` flag on each account row and slot record,
  never rolled back.
  - Set by actual loads and writes, not by EIP-2929 warming or EIP-2930
    prewarming.
  - Precompiles, system-call targets without code, the coinbase, withdrawal
    recipients, CREATE targets and 7702 authorities are included as revm
    includes them.
- **Changes, lazily.** Each account and slot remembers the BAL index it was
  last written in and its value at the start of that index.
  - The first write in a new index records the old index's net change, if any,
    and the final pass closes what is still open. Nothing walks the state per tx.
  - A slot with no change becomes a read.
- **Order from the prover.** The BalHint input lists the keys in BAL order. The
  guest checks it in one pass: strictly increasing, every key accessed, and the
  counts equal to the accessed counts, so it is exactly the accessed set. It
  then encodes the RLP in that order and hashes it once. (Replaced in v12 by
  sorted-order links over the StateRoot rows; see "Every loaded key is a
  leaf".)
- **Size limit.** `accounts + slots ≤ gas_limit / 2000`, or the block is
  invalid.

A corrupted BAL now yields either a different block hash or a fatal hint
check. All 102 invalid 7928 blocks are rejected.

| EIP | Blocks | evmone pass | zevm pass | FAIL_NEG (evmone) |
|---|---:|---:|---:|---:|
| 2780 | 283 | 283 | 274 | 0 |
| 7708 | 77 | 77 | 26 | 0 |
| 7778 | 117 | 117 | 56 | 0 |
| 7843 | 23 | 23 | 0 | 0 |
| 7928 | 1,248 | 1,248 | 558 | 0 |
| 7954 | 58 | 58 | 28 | 0 |
| 7976 | 543 | 543 | 531 | 0 |
| 7981 | 189 | 189 | 173 | 0 |
| 7997 | 40 | 40 | 1 | 0 |
| 8024 | 288 | 288 | 176 | 0 |
| 8037 | 834 | 834 | 290 | 0 |
| 8038 | 263 | 263 | 49 | 0 |
| 8246 | 663 | 663 | 5 | 0 |
| 8282 | 356 | 356 | 145 | 0 |
| **total** | **4,982** | **4,982** | **2,312** | **0** |

zevm accepts no invalid block either (it was at 74 FAIL_NEG). Its 8037 count
drops by 4 (294 → 290):
- `inner_create_succeeds_code_deposit_state_gas` and
  `max_initcode_size_gas_metering_via_create` end in a halting outer frame, so
  their state comes out the same either way;
- zevm, without the 8038 costs, never reaches the inner CREATE that the BAL now
  records.

**Fork transition** (`for_bpo2toamsterdamattime15k`): 366 PASS, 35 PASS_NEG,
2 MISSING (undecodable headers), 0 FAIL.


From Amsterdam the size limits rise:
- deployed code: 24,576 → 65,536 bytes;
- init code: 49,152 → 131,072 bytes.

The guest checks deployed code on CREATE / CREATE2 and on creation txs, and
checks the init code of creation txs. zevm checks the CREATE / CREATE2 init
code. evmone already had the in-VM check.

| EIP | Blocks | evmone pass | zevm pass | FAIL_NEG (evmone) |
|---|---:|---:|---:|---:|
| 2780 | 283 | 283 | 270 | 0 |
| 7708 | 77 | 77 | 26 | 0 |
| 7778 | 117 | 117 | 56 | 0 |
| 7843 | 23 | 23 | 0 | 0 |
| 7928 | 1,248 | 1,148 | 524 | 100 |
| 7954 | 58 | 58 | 28 | 0 |
| 7976 | 543 | 543 | 531 | 0 |
| 7981 | 189 | 189 | 173 | 0 |
| 7997 | 40 | 40 | 1 | 0 |
| 8024 | 288 | 288 | 176 | 0 |
| 8037 | 834 | 834 | 294 | 0 |
| 8038 | 263 | 263 | 49 | 0 |
| 8246 | 663 | 663 | 5 | 0 |
| 8282 | 356 | 356 | 145 | 0 |
| **total** | **4,982** | **4,882** | **2,278** | **100** |

**evmone failures left:** only the 100 7928 FAIL_NEG, which are invalid
block-level access lists that the guest doesn't check yet.

**Fork transition** (`for_bpo2toamsterdamattime15k`):
- 366 PASS, 34 PASS_NEG, 2 MISSING;
- 1 FAIL_NEG, 7928's BAL size check.

zevm's 30 remaining 7954 blocks fail on gas, against evmone runs of the
same blocks that pass. The gaps (e.g. 2,500 gas) come from the 8038 access
costs and 8024 opcodes that zevm lacks, not from the size limits or jumpdest
analysis of large code.

### After EIP-8282

At the end of every Amsterdam block, after 7002 and 7251, the builder deposit
(`0x0000BFF4…8282`, type `0x03`) and builder exit (`0x000064D6…8282`, type
`0x04`) predeploys are called. The rules are the same as 7002 / 7251:
- an empty contract or a failed call makes the block invalid;
- the output is appended to the requests as opaque bytes.

Logs that a system contract emits are now discarded in every fork. They
used to land in the last tx's receipt, or, at block start, write past an
empty receipt list.

| EIP | Blocks | evmone pass | zevm pass | FAIL_NEG (evmone) |
|---|---:|---:|---:|---:|
| 2780 | 283 | 283 | 270 | 0 |
| 7708 | 77 | 77 | 26 | 0 |
| 7778 | 117 | 117 | 56 | 0 |
| 7843 | 23 | 23 | 0 | 0 |
| 7928 | 1,248 | 1,148 | 524 | 100 |
| 7954 | 58 | 34 | 6 | 0 |
| 7976 | 543 | 543 | 531 | 0 |
| 7981 | 189 | 189 | 173 | 0 |
| 7997 | 40 | 40 | 0 | 0 |
| 8024 | 288 | 288 | 176 | 0 |
| 8037 | 834 | 831 | 291 | 0 |
| 8038 | 263 | 263 | 49 | 0 |
| 8246 | 663 | 663 | 5 | 0 |
| 8282 | 356 | 356 | 145 | 0 |
| **total** | **4,982** | **4,855** | **2,252** | **100** |

**evmone failures left:**
- **7928:** the 100 FAIL_NEG. They are invalid block-level access lists,
  which the guest doesn't check yet.
- **7954** (code size): 24 blocks, plus 3 8037 code-deposit / oversized-initcode
  blocks.

**Fork transition** (`for_bpo2toamsterdamattime15k`):
- 355 PASS, 34 PASS_NEG, 2 MISSING;
- the 11 FAIL are 7954 and the 1 FAIL_NEG is 7928's BAL size check.

### After EIP-8246

SELFDESTRUCT no longer burns ETH (Amsterdam):
- **To itself:** a contract created in the same tx that self-destructs to
  itself keeps its balance.
- **End of tx:** a destroyed account that still holds a balance (value received
  after the SELFDESTRUCT, its own balance, or a coinbase's priority fee) becomes
  a balance-only account. Its nonce, code and storage are cleared.
- A destroyed account with a zero balance is deleted as before.

| EIP | Blocks | evmone pass | zevm pass | FAIL_NEG (evmone) |
|---|---:|---:|---:|---:|
| 2780 | 283 | 283 | 270 | 0 |
| 7708 | 77 | 77 | 26 | 0 |
| 7778 | 117 | 117 | 56 | 0 |
| 7843 | 23 | 23 | 0 | 0 |
| 7928 | 1,248 | 1,132 | 518 | 100 |
| 7954 | 58 | 34 | 6 | 0 |
| 7976 | 543 | 543 | 531 | 0 |
| 7981 | 189 | 189 | 173 | 0 |
| 7997 | 40 | 40 | 0 | 0 |
| 8024 | 288 | 288 | 176 | 0 |
| 8037 | 834 | 821 | 287 | 2 |
| 8038 | 263 | 263 | 49 | 0 |
| 8246 | 663 | 663 | 5 | 0 |
| 8282 | 356 | 134 | 90 | 6 |
| **total** | **4,982** | **4,607** | **2,187** | **108** |

**evmone failures left outside 7928 / 8282:**
- **7954** (code size): 24 blocks, plus 3 8037 code-deposit /
  oversized-initcode blocks that hit 7954's size limits.
- **8037 system-call boundaries:** 10 blocks, including 2 FAIL_NEG.

zevm's 8246 blocks fail on 8038 costs (e.g. CREATE is ~40,000 gas off), not
on the burn.

### After EIP-7976 and EIP-7981

- **EIP-7976:** the calldata floor is 64 gas per byte, zero or not.
- **EIP-7981:** the floor also counts access-list bytes (20 per address, 32
  per key) at the same rate. Access-list items cost 2,900 + 20 × 64 per
  address and 2,000 + 32 × 64 per key.
- **EIP-7778** needed no new code: its rule came with 8037. Its last 19 blocks
  were calldata-floor and access-list cases.

| EIP | Blocks | evmone pass | zevm pass | FAIL_NEG (evmone) |
|---|---:|---:|---:|---:|
| 2780 | 283 | 282 | 269 | 0 |
| 7708 | 77 | 77 | 26 | 0 |
| 7778 | 117 | 117 | 56 | 0 |
| 7843 | 23 | 23 | 0 | 0 |
| 7928 | 1,248 | 1,131 | 518 | 100 |
| 7954 | 58 | 34 | 6 | 0 |
| 7976 | 543 | 543 | 531 | 0 |
| 7981 | 189 | 189 | 173 | 0 |
| 7997 | 40 | 40 | 0 | 0 |
| 8024 | 288 | 288 | 176 | 0 |
| 8037 | 834 | 811 | 286 | 2 |
| 8038 | 263 | 262 | 48 | 0 |
| 8246 | 663 | 533 | 1 | 0 |
| 8282 | 356 | 134 | 90 | 6 |
| **total** | **4,982** | **4,464** | **2,180** | **108** |

**evmone failures left outside 7928 / 8246 / 8282:**
- **7954** (code size): 24 blocks.
- **8246** (SELFDESTRUCT no longer burns): 2780's last block, 8038's last
  block, and 7 8037 blocks (calls to an account self-destructed in the same
  tx, self-destruct in a create tx).
- **8037 system-call boundaries:** 8 blocks plus 2 FAIL_NEG
  (`system_call_execution_*`, `system_call_reservoir_boundary`).
- **8037 code-deposit and oversized-initcode cases:** 3 blocks, which reach
  7954's new size limits.

zevm still trails on everything that runs in-VM 8038 / 7843 / 8024 / 7954
costs or opcodes.

### After EIP-7708

EIP-7708 logs every non-zero ETH move between two distinct accounts (tx value,
CALL, CREATE endowment, SELFDESTRUCT to another account) as a LOG3 from
`0xff…fe`. Same fixtures and guests as below:

| EIP | Blocks | evmone pass | zevm pass | FAIL_NEG (evmone) |
|---|---:|---:|---:|---:|
| 2780 | 283 | 237 | 224 | 7 |
| 7708 | 77 | 73 | 22 | 0 |
| 7778 | 117 | 98 | 48 | 0 |
| 7843 | 23 | 23 | 0 | 0 |
| 7928 | 1,248 | 767 | 352 | 100 |
| 7954 | 58 | 28 | 6 | 0 |
| 7976 | 543 | 201 | 190 | 142 |
| 7981 | 189 | 9 | 9 | 26 |
| 7997 | 40 | 38 | 0 | 0 |
| 8024 | 288 | 288 | 176 | 0 |
| 8037 | 834 | 765 | 253 | 6 |
| 8038 | 263 | 175 | 29 | 4 |
| 8246 | 663 | 533 | 1 | 0 |
| 8282 | 356 | 129 | 85 | 6 |
| **total** | **4,982** | **3,364** | **1,395** | **291** |

- **Remaining 2780 / 7708 failures** all belong to other EIPs:
  - the 7976 calldata floor: expected − actual gas is 64 × the input bytes;
  - 7981 access-list prices: typed txs, and access-listed recipients and
    delegates;
  - one self-destruct-to-self with value that expects the balance kept (8246).
- **zevm's 7708 gap is 8038:** on the same blocks zevm charges the Osaka
  call costs (e.g. 36 gas short).
- **FAIL_NEG 233 → 291:** 52 of the 58 new ones are 7928 blocks that expect
  `INVALID_BLOCK_ACCESS_LIST` / `BLOCK_ACCESS_LIST_GAS_LIMIT_EXCEEDED`; the other 6 are
  8282 blocks that expect `SYSTEM_CONTRACT_CALL_FAILED`. They used to be
  rejected only because of a missing transfer log, and close with those EIPs.

### After EIP-8037 and EIP-2780

Same fixtures, evmone and zevm guests. The zevm gap is the in-VM EIPs evmone
v0.24 already has (see Open items).

| EIP | Blocks | evmone pass | zevm pass | FAIL_NEG (evmone) |
|---|---:|---:|---:|---:|
| 2780 | 283 | 160 | 149 | 7 |
| 7708 | 77 | 25 | 11 | 0 |
| 7778 | 117 | 98 | 48 | 0 |
| 7843 | 23 | 23 | 0 | 0 |
| 7928 | 1,248 | 683 | 335 | 48 |
| 7954 | 58 | 28 | 6 | 0 |
| 7976 | 543 | 201 | 190 | 142 |
| 7981 | 189 | 9 | 9 | 26 |
| 7997 | 40 | 33 | 0 | 0 |
| 8024 | 288 | 288 | 176 | 0 |
| 8037 | 834 | 721 | 249 | 6 |
| 8038 | 263 | 155 | 28 | 4 |
| 8246 | 663 | 109 | 1 | 0 |
| 8282 | 356 | 115 | 91 | 0 |
| **total** | **4,982** | **2,648** | **1,293** | **233** |

FAIL_NEG went up (114 → 233): with the gas now right, invalid blocks that
were rejected only because of a wrong gas total are now accepted. They expect
an intrinsic-gas / floor error (7976, 7981) or a block-access-list error
(7928), and close with those EIPs.

### After the guest groundwork

The guest accepts Amsterdam, so each EIP's own failures show. Pass counts
include `PASS_NEG`. A block can pass before its EIP is implemented: it passes
whenever its transactions don't touch any changed rule. So a non-zero count does
not mean the EIP is done.

`FAIL_NEG` counts invalid Amsterdam blocks the guest accepts. These are
soundness gaps, and each one closes with its EIP's validity rule.

| EIP | Blocks | evmone pass | zevm pass | FAIL_NEG (evmone) |
|---|---:|---:|---:|---:|
| 2780 | 283 | 30 | 30 | 4 |
| 7708 | 77 | 0 | 0 | 0 |
| 7778 | 117 | 50 | 42 | 0 |
| 7843 | 23 | 0 | 0 | 0 |
| 7928 | 1,248 | 295 | 293 | 25 |
| 7954 | 58 | 5 | 5 | 0 |
| 7976 | 543 | 122 | 122 | 66 |
| 7981 | 189 | 16 | 14 | 16 |
| 7997 | 40 | 0 | 0 | 0 |
| 8024 | 288 | 0 | 0 | 0 |
| 8037 | 834 | 115 | 98 | 2 |
| 8038 | 263 | 8 | 8 | 1 |
| 8246 | 663 | 0 | 0 | 0 |
| 8282 | 356 | 82 | 82 | 0 |
| **total** | **4,982** | **723** | **694** | **114** |

Regressions are unchanged with the groundwork in place:

- The full `tests-v5.4.0` corpus plus the legacy `InvalidBlocks` suites give
  identical results block for block on evmone v0.21 and v0.24.
- The Prague + Osaka subset is at 0 FAIL on both backends.
- Mainnet block 26167511 matches the chain hash on the host (both backends) and
  on both ZisK ELFs (GCC 14).

## External audit remediation (2026-10)

An external static audit of the C++ guest reported 9 findings. All were verified
against the code; the remediation (branch work on top of `24492dd`) is:

- **#3 BLOCKHASH (Critical).** `ZiskStateDB::get_block_hash` now serves the opcode
  from the EIP-2935 history-storage contract (`0x…2935`, slot `n % 8191`), read
  directly and trie-authenticated against the committed parent state root — the
  prover can no longer forge or zero an ancestor via a sparse/unlinked input set.
  A present-but-zero slot (only possible in the <256-block warm-up right after
  the Prague transition, which cannot occur on the live post-Prague networks)
  falls back to the input ancestor set; an *absent* slot halts (never a forgeable
  zero). Pre-Prague keeps the ancestor path (EEST only).
- **#1/#2/#8 fork + blob schedule (Critical/Low).** By default (the safe
  behavior, no flag needed), `ConsensusInfo::fork_id()` and the three blob
  accessors derive their values from the block's committed timestamp via the
  compile-time per-`ZEG_CHAIN` table in `zeg/fork_schedule.hpp` (mirroring
  `rust-input-gen`'s `fork_params`), ignoring the prover-supplied input fields.
  Mainnet has no Amsterdam row, so a mainnet ELF never activates Amsterdam (#8).
  The opt-out `ZEG_FORK_FROM_INPUT` reverts to reading the fork/blob from the
  input; it is used ONLY by EEST builds, which replay historical forks at
  synthetic activation times. No ZEG0 format change.
- **#4 strict RLP (High).** `rlp::decode_item` rejects non-canonical encodings
  (bare single byte, needless long form, leading-zero lengths); `as_u64`/`as_u256`
  reject leading zeros; tx envelopes reject trailing bytes and extra list fields.
- **#5 low-s (High).** `recover_sender` enforces `s ∈ [1, secp256k1n/2]`
  (`is_canonical_low_s`, shared with EIP-7702 auths). The ECRECOVER precompile
  (0x01) stays malleable per spec.
- **#9 input bounds (Low).** Stream reads are bounded to the input buffer
  (`zeg/stream.hpp` + per-section `count`/size pre-checks); a truncated or
  oversized-`count` input halts cleanly instead of reading out of bounds.

Two findings are not code changes:

- **#6 NewPayloadRequest root shape (interop).** The audit read EIP-8025's text
  (plain `Container` + `ProgressiveList` versioned_hashes). The guest instead
  follows consensus-specs **gloas**, which is what the **deployed Lighthouse**
  (`sigp/lighthouse` `unstable` ≥ `16ce0a0728`) actually implements: the outer
  `NewPayloadRequest` is a `progressive_container active_fields(1,1,1,1)`,
  `versioned_hashes` a bounded `VariableList<Hash256, U4096>`, and
  `ExecutionPayloadGloas` a 19-field progressive container — matching
  `new_payload_request.cpp` exactly. This is why live Sepolia proofs verify VALID.
  **No change**: the guest intentionally tracks Lighthouse, not the EIP-8025 text
  (`scripts/npr_root_ref.py` documents the intent). Monitor upstream convergence.
- **#7 invalidity result (completeness).** The guest halts on an invalid block
  rather than emitting a provable `false` `StatelessValidationResult`. This is
  sound (an invalid block simply yields no proof). Adopting the full EIP-8025
  result schema (a `valid` bool + explicit `chain_id`/`schema_id`) is a tracked
  follow-up, to be designed with #6's output shape against what the PE/Lighthouse
  consume. Note #1's enforcement already binds the fork via the committed
  timestamp and `kChainId`, closing most of #7's "nothing binds the fork" concern.

**Deploy note:** the deployed ELF needs only the usual `-DZEG_CHAIN=…` — fork/blob
enforcement is the default (safe). The EEST conformance build must add
`-DZEG_FORK_FROM_INPUT=ON` to replay historical forks at synthetic activation
times. All guest changes above are root-preserving for valid live blocks, so the
new ELF yields the same NewPayloadRequest roots as the current one (the
re-mint/redeploy and PE re-pin are still required because the ELF bytes change).
