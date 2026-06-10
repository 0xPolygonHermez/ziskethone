cmake_minimum_required(VERSION 3.22)

# Emit compile_commands.json so the VS Code C/C++ extension picks up the
# real compile flags (notably -std=c++20 and the FetchContent include
# paths) and stops complaining about std::assume_aligned, etc.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ----- evmone (static) bootstrap ---------------------------------------------
#
# evmone uses the Hunter package manager for its transitive C++ deps
# (intx, ethash, …). Hunter has a hard requirement: `HunterGate()` must be
# called *before* the outer project()'s `project()` command. So we have to
# (a) download evmone's source first, (b) include its Hunter setup, and
# only then (c) call our `project()`. After that we add_subdirectory it.
include(FetchContent)

FetchContent_Declare(
    evmone
    GIT_REPOSITORY https://github.com/ethereum/evmone.git
    GIT_TAG        v0.21.0
)

# FetchContent_Populate (without add_subdirectory) is deprecated since
# CMake 3.30. CMP0169 OLD silences the warning while keeping the behaviour
# we need (raw download without configuring yet).
if(POLICY CMP0169)
    cmake_policy(SET CMP0169 OLD)
endif()
FetchContent_GetProperties(evmone)
if(NOT evmone_POPULATED)
    FetchContent_Populate(evmone)
endif()

# Apply our local evmone patches. Both align evmone's CALL gas accounting
# with revm's behavior so a stateless witness recorded by reth/revm is
# sufficient for evmone — no extra host calls outside the witness:
#   01: Reorder CALL gas checks to charge CALL_VALUE_COST first, then cold
#       access, then ACCOUNT_CREATION_COST, then the EIP-7702 delegation
#       probe — mirrors revm's `load_acc_and_calc_gas`. A value-bearing
#       CALL destined to OOG no longer invokes any host state query.
#   02: In get_delegate_address, fast-bail via host.get_code_hash before
#       calling host.copy_code — an EOA (or any account with empty code)
#       can never carry an EIP-7702 designator. Mirrors revm's
#       `Bytecode::eip7702_address(account.code)` short-circuit.
# Each patch is checked with `git apply --reverse --check` first; if it
# is already applied we skip — that keeps the configure step idempotent
# across rebuilds.
set(_evmone_patches
    "${CMAKE_CURRENT_SOURCE_DIR}/patches/01-evmone-revm-aligned-call-gas-order.patch"
    "${CMAKE_CURRENT_SOURCE_DIR}/patches/02-evmone-delegation-eoa-fastpath.patch"
)
find_program(GIT_EXECUTABLE git REQUIRED)
foreach(_patch IN LISTS _evmone_patches)
    execute_process(
        COMMAND ${GIT_EXECUTABLE} apply --reverse --check "${_patch}"
        WORKING_DIRECTORY "${evmone_SOURCE_DIR}"
        RESULT_VARIABLE _already_applied
        OUTPUT_QUIET ERROR_QUIET)
    if(NOT _already_applied EQUAL 0)
        execute_process(
            COMMAND ${GIT_EXECUTABLE} apply "${_patch}"
            WORKING_DIRECTORY "${evmone_SOURCE_DIR}"
            RESULT_VARIABLE _apply_rc)
        if(NOT _apply_rc EQUAL 0)
            message(FATAL_ERROR
                "Failed to apply evmone patch ${_patch} (rc=${_apply_rc})")
        endif()
        message(STATUS "Applied evmone patch: ${_patch}")
    else()
        message(STATUS "evmone patch already applied: ${_patch}")
    endif()
endforeach()

# Pull evmone's Cable/Hunter setup into *this* CMakeLists scope before we
# call project(), so Hunter is happy and Cable's toolchain configuration
# takes effect on our build too.
include(${evmone_SOURCE_DIR}/cmake/cable/bootstrap.cmake)
include(CableToolchains)
include(CableBuildType)
include(CableCompilerSettings)
cable_configure_toolchain(DEFAULT cxx17-pic)
cable_set_build_type(DEFAULT Release CONFIGURATION_TYPES Release Debug)
include(${evmone_SOURCE_DIR}/cmake/Hunter/init.cmake)

project(zisk_eth_guest CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Static link for evmone + every transitive lib it pulls.
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(EVMONE_TESTING       OFF CACHE BOOL "" FORCE)
set(EVMONE_FUZZING       OFF CACHE BOOL "" FORCE)
set(EVMONE_PRECOMPILES_SILKPRE OFF CACHE BOOL "" FORCE)

add_subdirectory(${evmone_SOURCE_DIR} ${evmone_BINARY_DIR})

# evmone::state provides `is_precompile` + `call_precompile` (ECRECOVER,
# SHA256, RIPEMD160, IDENTITY, MODEXP, BN254 ops, BLAKE2F, KZG-PE, BLS12,
# P256). It's only built automatically when EVMONE_TESTING=ON; we add it
# manually because the cpp-guest needs precompile dispatch but doesn't
# want the rest of evmone's test infrastructure (GoogleTest etc.). Pure
# `evmone::precompiles` + `evmc::evmc_cpp` deps; no test-only requirements.
add_subdirectory(${evmone_SOURCE_DIR}/test/state ${evmone_BINARY_DIR}/test_state EXCLUDE_FROM_ALL)
# state's CMakeLists exports `PUBLIC ${PROJECT_SOURCE_DIR}` for its
# include path, but PROJECT_SOURCE_DIR there resolves to OUR project
# (cpp-guest) because there's no `project()` call inside test/state.
# Override the PUBLIC include path to point at evmone's source root so
# `#include <test/state/precompiles.hpp>` resolves.
target_include_directories(evmone-state PUBLIC ${evmone_SOURCE_DIR})

# ----- guest executable ------------------------------------------------------
#
# NOTE: For an actual ZisK build, the toolchain must target the ZisK RISC-V
# zkVM (riscv64ima-zisk-zkvm-elf). C++ guest support in ZisK is still
# experimental and lives outside this CMakeLists for now.
#
# evmone v0.21.0 absorbed evmc into the same library, so a single `evmone`
# link target gives us both the EVM and the `evmc::Host` interface that
# ZiskStateDB implements.

set(GUEST_SOURCES
    src/main.cpp
    src/fatal.cpp
    src/accounts.cpp
    src/block_header.cpp
    src/bloom.cpp
    src/consensus_info.cpp
    src/contracts.cpp
    src/create_address.cpp
    src/dynamic_storage.cpp
    src/eip6110_deposit.cpp
    src/fake_exponential.cpp
    src/hex_prefix.cpp
    src/intrinsic_gas.cpp
    src/journal.cpp
    src/mpt.cpp
    src/previous_blocks.cpp
    src/receipt.cpp
    src/rlp.cpp
    src/state_root.cpp
    src/storages.cpp
    src/transactions.cpp
    src/transient_storage.cpp
    src/zisk_crypto.cpp
    src/zisk_state_db.cpp
)
# Wire the chosen backend. Only one source-side provider object is
# included: the weak host stub would otherwise satisfy the symbol
# before the linker visits any archive (weak objects in the main link
# line win over archive-member resolution).
# secp256k1 ECDSA recover: the single source shared with the ZisK ELF
# (cpp-guest/zisk/secp256k1.cpp). Without ZEG_ZISK it compiles its host path,
# which delegates to evmone's reference recover (linked below) — fast, and the
# differential oracle for the in-circuit ZisK implementation.
list(APPEND GUEST_SOURCES zisk/secp256k1.cpp)

# ----- EVM backend selection -------------------------------------------------
#
# The guest drives an EVM through the evmc2 interface (see ZiskStateDB::vm2_ /
# execute2), so the interpreter is swappable. `evmone` (default) uses the
# upstream interpreter via evmc2_create_evmone; `zevm` uses our hand-written
# interpreter (cpp-guest/src/zevm) via evmc2_create_zevm. evmone's baseline is
# currently cheaper on ZisK for contract-heavy blocks (~30% fewer steps on a
# real 52M-gas block), so it's the default. Both paths still link
# evmone::precompiles + evmone::state because precompile dispatch lives in the
# host/state layer.
set(EVM_BACKEND "evmone" CACHE STRING "EVM implementation: evmone | zevm")
set_property(CACHE EVM_BACKEND PROPERTY STRINGS evmone zevm)

add_executable(zisk_eth_guest ${GUEST_SOURCES})

target_include_directories(zisk_eth_guest PUBLIC include)
# evmone's baseline.hpp / vm.hpp (CodeAnalysis + the pre-analyzed execute()
# overload used by the analysis cache) live under lib/, not the public include/.
# include/ holds evmmax/evmmax.hpp, pulled in by evmone_precompiles/secp256k1.hpp
# (the host secp256k1 recover path).
target_include_directories(zisk_eth_guest PRIVATE
    ${evmone_SOURCE_DIR}/lib
    ${evmone_SOURCE_DIR}/include)
target_compile_options(zisk_eth_guest PRIVATE -Wall -Wextra -Wpedantic)
# intx::intx is used directly by the guest sources (e.g. fake_exponential,
# zisk_state_db), independent of which EVM backend is linked. It used to come
# in transitively via the `evmone` target's PUBLIC deps; the precompiles/state
# targets only link it PRIVATEly, so when the zevm backend drops the `evmone`
# link we lose the <intx/intx.hpp> include path. evmone's Hunter setup leaves
# intx_DIR in the cache, so re-import the (subdirectory-scoped) target here to
# get it visible at this scope, then link it explicitly.
find_package(intx CONFIG QUIET)
target_link_libraries(zisk_eth_guest PRIVATE evmone::precompiles evmone::state intx::intx)

if(EVM_BACKEND STREQUAL "zevm")
    add_subdirectory(src/zevm)
    target_link_libraries(zisk_eth_guest PRIVATE zevm)
    # Selects evmc2_create_zevm() over evmc2_create_evmone() at the VM-creation
    # site in zisk_state_db.cpp.
    target_compile_definitions(zisk_eth_guest PRIVATE USE_ZEVM)
elseif(EVM_BACKEND STREQUAL "evmone")
    # evmc2_create_evmone wraps evmone baseline; only built for this backend
    # (it needs evmone's headers + lib, which the zevm backend doesn't link).
    target_sources(zisk_eth_guest PRIVATE src/evmc2_evmone.cpp)
    target_link_libraries(zisk_eth_guest PRIVATE evmone)
else()
    message(FATAL_ERROR "EVM_BACKEND must be evmone | zevm (got ${EVM_BACKEND})")
endif()

