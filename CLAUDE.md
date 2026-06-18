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

## Verify a single block

```bash
HEAD=$(curl -s -X POST http://localhost:8545 -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' | grep -o '0x[0-9a-f]*')
BLK=$(( HEAD - 3 ))
./target/release/input-gen --rpc-url http://localhost:8545 --block $BLK --output build/block_input.bin
./cpp-guest/build-zevm/zisk_eth_guest build/block_input.bin | tail -1   # must match:
./cpp-guest/build/zisk_eth_guest     build/block_input.bin | tail -1
```
