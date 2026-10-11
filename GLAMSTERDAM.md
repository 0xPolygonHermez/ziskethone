# Glamsterdam (Amsterdam) — implementation tracker

Glamsterdam is the Ethereum upgrade after Fusaka; **Amsterdam** is its
execution-layer half (the consensus half is Gloas). It activated on Sepolia on
2026-10-06; mainnet is not scheduled yet.

This branch has the test pipeline ready, and the guest does not implement
Amsterdam yet:

- `eest-witness-gen` is on **reth v2.7.0** (the first release with Amsterdam on
  Sepolia). It maps the `Amsterdam` and `…ToAmsterdamAtTime…` networks, with blob
  parameters from the fixture's `blobSchedule`. It also writes the new header
  fields (`blockAccessListHash`, `slotNumber`) into the manifest.
- `input-gen` emits `fork_id = 8` (Amsterdam) for any header that carries
  `block_access_list_hash`.
- The guest still stops at Osaka, so it rejects every Amsterdam block with
  `guest: ConsensusInfo: unknown fork_id`. `scripts/eest_sweep.sh` counts that
  as `FAIL(unsupported_fork)`. It is not counted as `PASS_NEG`, even for an
  invalid-block test.

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
| [8037](https://eips.ethereum.org/EIPS/eip-8037) | State creation gas cost increase (state-gas reservoir) | `eip8037_state_creation_gas_cost_increase` | 270 / 834 | todo |
| [8038](https://eips.ethereum.org/EIPS/eip-8038) | State access gas cost increase | `eip8038_state_access_gas_cost_increase` | 88 / 263 | todo |
| [8070](https://eips.ethereum.org/EIPS/eip-8070) | eth/72 sparse blobpool | — | — | n/a (networking only) |
| [8246](https://eips.ethereum.org/EIPS/eip-8246) | Remove SELFDESTRUCT burn | `eip8246_selfdestruct_no_burn` | 9 / 663 | todo |
| [8282](https://eips.ethereum.org/EIPS/eip-8282) | Builder execution requests | `eip8282_builder_execution_requests` | 22 / 356 | todo |

### Guest groundwork (needed before any EIP can pass)

Every Amsterdam block fails until the guest accepts the fork:

1. Add `ForkId::Amsterdam = 8` (`cpp-guest/include/zeg/fork.hpp`), map it to an
   Amsterdam EVM revision and a 23-field header, and raise the `unknown fork_id`
   gate in `consensus_info.cpp`. The pinned evmone (v0.21.0) stops at
   `EVMC_OSAKA`. evmone **v0.24.0** has the Amsterdam revision, including
   EIP-8037's state-gas reservoir (EVMC ABI 19: `state_gas` in
   `evmc_message`/`evmc_result`) and EIP-8038. Bumping it is the natural first
   step, and zevm needs the same revision.
2. Carry `block_access_list_hash` and `slot_number` in `ConsensusInfo` (a
   `BINARY_FORMAT.md` change), so the guest can hash the Amsterdam header.
3. Validate `block_access_list_hash` by building the BAL during execution
   (EIP-7928). Until then, the header hash can only be correct by trusting the
   declared value.

## Baseline (all failing)

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
