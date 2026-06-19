# ziskethone — guidance for Claude

## Block verification / witnesses

- The local Ethereum RPC is at `http://localhost:8545` (reth).
- The node only serves **state for ~32 recent blocks**. When generating a witness
  with `input-gen` (or any verification that needs state), **never target a block
  more than 32 blocks older than the current head**. Always read the head first
  (`eth_blockNumber`) and pick a block within 32 of it (e.g. `head - 3`).
- A witness for a too-old block fails with "block N not found" / no state.

## EVM backends

- The guest drives the EVM through the evmc2 interface; the backend is a build-time
  choice via the `EVM_BACKEND` CMake option (`evmone` default, or `zevm`). Use a
  separate build dir per backend:
  - `cmake -S cpp-guest -B cpp-guest/build      -DEVM_BACKEND=evmone` → `build/zisk_eth_guest`
  - `cmake -S cpp-guest -B cpp-guest/build-zevm -DEVM_BACKEND=zevm`   → `build-zevm/zisk_eth_guest`

## RISC-V ELF cross-compiler — use GCC 14, NOT GCC 15

The ZisK guest ELF (`cpp-guest/zisk`) must be built with **xpack `riscv-none-elf-gcc`
14.x**. **GCC 15.2.0 miscompiles the zevm guest** at the aggressive `-O3 ZEG_GUEST_OPT`
flags and produces a *wrong block-state root* (verified: host g++ 13 + full Prague
EEST pass; the wrong hash even differs between -O1 and -O3 — a codegen bug). Ubuntu's
`riscv64-unknown-elf-g++` 13.2.0 ships no libstdc++ headers, so it can't build the C++
guest at all. Put the gcc-14 `bin/` on `PATH`; `toolchain.cmake` auto-detects
`riscv-none-elf-`.

## Verify a single block

```bash
HEAD=$(curl -s -X POST http://localhost:8545 -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' | grep -o '0x[0-9a-f]*')
BLK=$(( HEAD - 3 ))
./target/release/input-gen --rpc-url http://localhost:8545 --block $BLK --output build/block_input.bin
./cpp-guest/build-zevm/zisk_eth_guest build/block_input.bin | tail -1   # must match:
./cpp-guest/build/zisk_eth_guest     build/block_input.bin | tail -1
```
