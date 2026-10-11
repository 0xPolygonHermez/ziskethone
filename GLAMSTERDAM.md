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
  `block_access_list_hash`. The binary format is v10 and carries both new header
  fields (see `BINARY_FORMAT.md`).
- The guest accepts Amsterdam: `ForkId::Amsterdam` → `EVMC_AMSTERDAM`, the
  23-field header for the current block and its ancestors, SLOTNUM's
  `block_slot_number` in the tx context, and `is_amsterdam_or_later()`.
- The guest is on **evmone v0.24.0** (EVMC ABI 19, Amsterdam revision). zevm is
  ported to the same ABI and has an `EVMC_AMSTERDAM` dispatch loop, which for
  now has the Osaka opcode set.

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
| [2780](https://eips.ethereum.org/EIPS/eip-2780) | Resource-based intrinsic tx gas | `eip2780_reduce_intrinsic_tx_gas` | 61 / 283 | todo |
| [7708](https://eips.ethereum.org/EIPS/eip-7708) | ETH transfers emit a log | `eip7708_eth_transfer_logs` | 40 / 77 | todo |
| [7778](https://eips.ethereum.org/EIPS/eip-7778) | Block gas accounting without refunds | `eip7778_block_gas_accounting_without_refunds` | 9 / 117 | todo |
| [7843](https://eips.ethereum.org/EIPS/eip-7843) | SLOTNUM opcode (+ `slot_number` header field) | `eip7843_slotnum` | 10 / 23 | todo |
| [7928](https://eips.ethereum.org/EIPS/eip-7928) | Block-level access lists (+ `block_access_list_hash` header field) | `eip7928_block_level_access_lists` | 211 / 1,248 | todo |
| [7954](https://eips.ethereum.org/EIPS/eip-7954) | Increase max contract size | `eip7954_increase_max_contract_size` | 22 / 58 | todo |
| [7976](https://eips.ethereum.org/EIPS/eip-7976) | Increase calldata floor cost | `eip7976_increase_calldata_floor_cost` | 21 / 543 | todo |
| [7981](https://eips.ethereum.org/EIPS/eip-7981) | Increase access list cost | `eip7981_increase_access_list_cost` | 19 / 189 | todo |
| [7997](https://eips.ethereum.org/EIPS/eip-7997) | Deterministic factory contract | `eip7997_deterministic_factory_contract` | 21 / 40 | todo |
| [8024](https://eips.ethereum.org/EIPS/eip-8024) | DUPN / SWAPN / EXCHANGE | `eip8024_dupn_swapn_exchange` | 66 / 288 | todo |
| [8037](https://eips.ethereum.org/EIPS/eip-8037) | State creation gas cost increase (state-gas reservoir) | `eip8037_state_creation_gas_cost_increase` | 270 / 834 | done (most fixtures also need 2780) |
| [8038](https://eips.ethereum.org/EIPS/eip-8038) | State access gas cost increase | `eip8038_state_access_gas_cost_increase` | 88 / 263 | todo |
| [8070](https://eips.ethereum.org/EIPS/eip-8070) | eth/72 sparse blobpool | — | — | n/a (networking only) |
| [8246](https://eips.ethereum.org/EIPS/eip-8246) | Remove SELFDESTRUCT burn | `eip8246_selfdestruct_no_burn` | 9 / 663 | todo |
| [8282](https://eips.ethereum.org/EIPS/eip-8282) | Builder execution requests | `eip8282_builder_execution_requests` | 22 / 356 | todo |

### Open items that span EIPs

- **Soundness: the BAL hash is trusted.** `block_access_list_hash` comes from
  the input and goes straight into the header hash
  (`TODO(EIP-7928)` in `run.cpp`). EIP-7928 must build the BAL during execution
  and check its hash against the input.
- **EIP-8037 is entangled with other EIPs.** Its fixtures use EIP-2780's
  intrinsic gas (e.g. a 15,000-gas plain call), EIP-8038's access costs and the
  EIP-7976/7981 floor, so most of them pass only once those are in. Its block
  accounting is also EIP-7778's rule (no refund in the block's gas).
- **Total tx gas cap.** `TX_MAX_TOTAL_GAS_LIMIT` (2^32 − 1) comes from
  execution-specs and the fixtures; revm 43 and reth 2.7 don't implement it.
- **System calls** get 30M regular gas plus a 16-slot state-gas reservoir, as
  evmone and the fixtures do. revm 43 gives 30M + 16 × 97,920 regular gas
  instead.
- **zevm** runs Amsterdam with Osaka opcodes and Osaka access costs; it has the
  EIP-8037 state gas. Each remaining EIP needs a zevm change alongside the host
  change: 8024 and 7843 opcodes, 8038 gas.
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
