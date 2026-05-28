# Zisk zkVM build for the ziskethone C++ Ethereum block guest.
#
# This is a SEPARATE build from cpp-guest/CMakeLists.txt (which is host-only,
# fetches evmone 0.21 via Hunter). This one cross-compiles to the Zisk
# RISC-V zkVM target and REUSES zilkworm's vendored, already-Zisk-patched
# evmone 0.19 + silkworm_core stack rather than building evmone fresh.
#
# Configure:
#   ZISK_TOOLCHAIN_PREFIX=<xpack-bin> cmake -B build-zisk -S zisk \
#       -DCMAKE_TOOLCHAIN_FILE=<zilkworm>/prover/guest_zisk/cmake/zisk-toolchain.cmake \
#       -GNinja
#   cmake --build build-zisk
# Output: build-zisk/zisk_eth_guest.elf
#   Run: ziskemu --sdk -X -e build-zisk/zisk_eth_guest.elf -i <wrapped-input>
#
# ZILKWORM_ROOT points at the zilkworm checkout whose third_party/ +
# zilk_core/ provide intx::intx, evmc, evmone, blst::blst and the patched
# silkworm::precompile::ecrec_run (evmone 0.19's ECRECOVER routes there).
cmake_minimum_required(VERSION 3.28)

set(ZILKWORM_ROOT "/home/dappnode/zilkworm" CACHE PATH
    "Path to the zilkworm checkout providing evmone 0.19 + silkworm_core.")
set(ZEG_GUEST_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)

# Bootstrap Cable (the cmake helper bundled with evmone) before project() —
# the same pattern guest_zisk uses. Provides CableBuildType / CableBuildInfo
# required by the evmone + blst plumbing in third_party/CMakeLists.txt.
include(${ZILKWORM_ROOT}/third_party/evmone/cmake/cable/bootstrap.cmake)
include(CableBuildType)
cable_set_build_type(DEFAULT Release CONFIGURATION_TYPES Release)

project(zisk_eth_guest LANGUAGES C CXX ASM)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Variable expected by zilkworm's third_party/ and zilk_core/ build glue.
set(SILKWORM_MAIN_DIR ${ZILKWORM_ROOT})

# Define ZISK globally before adding the zilkworm subdirs so all #ifdef ZISK
# gating (evmone_precompiles keccak/sha256 syscalls, ziskethone's own I/O
# gates) selects the bare-metal path.
add_compile_definitions(ZISK)
set(ZISK TRUE)

include(CableBuildInfo)
cable_add_buildinfo_library(PROJECT_NAME zilkworm GIT_DESCRIBE "" GIT_BRANCH "")

# Pull in the real zilkworm targets: intx::intx, evmc, evmone, blst::blst
# (third_party) and silkworm_core / silkworm_dev (zilk_core). silkworm_dev
# transitively exposes evmone/evmc/intx include paths and provides the
# silkworm::precompile::ecrec_run that evmone 0.19's ECRECOVER precompile
# calls into.
add_subdirectory(${ZILKWORM_ROOT}/third_party ${CMAKE_BINARY_DIR}/third_party)
add_subdirectory(${ZILKWORM_ROOT}/zilk_core   ${CMAKE_BINARY_DIR}/zilk_core)

# ----- guest executable ------------------------------------------------------
set(GUEST_SOURCES
    ${ZEG_GUEST_ROOT}/src/main.cpp
    ${ZEG_GUEST_ROOT}/src/fatal.cpp
    ${ZEG_GUEST_ROOT}/src/accounts.cpp
    ${ZEG_GUEST_ROOT}/src/block_header.cpp
    ${ZEG_GUEST_ROOT}/src/bloom.cpp
    ${ZEG_GUEST_ROOT}/src/consensus_info.cpp
    ${ZEG_GUEST_ROOT}/src/contracts.cpp
    ${ZEG_GUEST_ROOT}/src/create_address.cpp
    ${ZEG_GUEST_ROOT}/src/eip6110_deposit.cpp
    ${ZEG_GUEST_ROOT}/src/fake_exponential.cpp
    ${ZEG_GUEST_ROOT}/src/hex_prefix.cpp
    ${ZEG_GUEST_ROOT}/src/intrinsic_gas.cpp
    ${ZEG_GUEST_ROOT}/src/journal.cpp
    ${ZEG_GUEST_ROOT}/src/mpt.cpp
    ${ZEG_GUEST_ROOT}/src/previous_blocks.cpp
    ${ZEG_GUEST_ROOT}/src/receipt.cpp
    ${ZEG_GUEST_ROOT}/src/rlp.cpp
    ${ZEG_GUEST_ROOT}/src/state_root.cpp
    ${ZEG_GUEST_ROOT}/src/storages.cpp
    ${ZEG_GUEST_ROOT}/src/transactions.cpp
    ${ZEG_GUEST_ROOT}/src/transient_storage.cpp
    ${ZEG_GUEST_ROOT}/src/zisk_crypto.cpp
    ${ZEG_GUEST_ROOT}/src/zisk_state_db.cpp
    # ----- Zisk bare-metal runtime (copied from zilkworm guest_zisk) -----
    arena_malloc.cpp
    runtime_stubs.cpp
    memmove.cpp
    _start.s
    dma/memcpy.s
    dma/memset.s
    dma/memcmp.s
    libgcc_overrides.cpp
    # Zisk syscall override for evmone's SHA-256 precompile compression.
    precompiles/zisk_sha256.cpp
)

add_executable(zisk_eth_guest.elf ${GUEST_SOURCES})

target_include_directories(zisk_eth_guest.elf PRIVATE
    ${ZEG_GUEST_ROOT}/include   # zeg/*.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include  # zisk_io.h
)

# silkworm_dev publicly links silkworm_core + nlohmann_json, which
# propagates intx::intx / evmone / evmc include paths. evmone's
# test/state include path (for <test/state/precompiles.hpp>) and the
# evmone lib path (for <lib/evmone/vm.hpp>, <lib/evmone/tracing.hpp>)
# come from the evmone target's PUBLIC include dirs (evmone/include,
# evmone/lib) plus its INTERFACE "." — but <test/state/...> needs the
# evmone source root on the include path, which evmone exposes via its
# INTERFACE include of ".". Add it explicitly to be safe.
target_link_libraries(zisk_eth_guest.elf PRIVATE silkworm_dev evmone)
target_include_directories(zisk_eth_guest.elf PRIVATE
    ${ZILKWORM_ROOT}/third_party/evmone        # <test/state/...>, <lib/evmone/...>
)

# Per-function/data sections so the linker drops unreferenced libstdc++
# exception / FP / stdio machinery via --gc-sections.
target_compile_options(zisk_eth_guest.elf PRIVATE
    -ffunction-sections
    -fdata-sections
    -flto  # match zilkworm guest_zisk: cross-TU inlining
)

# -nostartfiles drops newlib's crt0; _start.s + zisk.ld replace it.
target_link_options(zisk_eth_guest.elf PRIVATE
    -nostartfiles
    -T ${CMAKE_CURRENT_SOURCE_DIR}/zisk.ld
    -Wl,--gc-sections
    -flto
)

set_property(TARGET zisk_eth_guest.elf APPEND PROPERTY LINK_DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/zisk.ld
)
