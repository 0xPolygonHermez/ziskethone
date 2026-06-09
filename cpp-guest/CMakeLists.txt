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

# ----- secp256k1_ecdsa_verify backend ---------------------------------------
#
# The cpp-guest declares one external syscall in zeg/zisk_crypto.hpp.
# SECP_BACKEND chooses which implementation provides it on the host:
#
#   zisk-libc       Link the real ZisK lib-c (GMP + NASM-tuned secp256k1
#                   at /Users/.../zisk/lib-c/c/). Requires nasm + GMP +
#                   x86-64 with ADX. Closest match to what the zkVM
#                   target ultimately runs.
#   libsecp256k1    Wrap Bitcoin's libsecp256k1 (Homebrew) with a thin
#                   C-ABI shim. Default on macOS — Rosetta doesn't
#                   translate the ADX/BMI2 instructions ZisK lib-c uses.
#   stub            Link the weak host stub that aborts on first use.
#                   Useful for builds without GMP / libsecp256k1.
if(APPLE)
    set(_SECP_DEFAULT "libsecp256k1")
else()
    set(_SECP_DEFAULT "zisk-libc")
endif()
set(SECP_BACKEND "${_SECP_DEFAULT}" CACHE STRING
    "secp256k1_ecdsa_verify backend: zisk-libc | libsecp256k1 | stub")
set_property(CACHE SECP_BACKEND PROPERTY STRINGS
             zisk-libc libsecp256k1 stub)
set(ZISK_LIBC_SRC "$ENV{HOME}/git/zisk/zisk/lib-c/c" CACHE PATH
    "Path to the ZisK lib-c source tree (used when SECP_BACKEND=zisk-libc).")

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
if(SECP_BACKEND STREQUAL "stub")
    list(APPEND GUEST_SOURCES src/zisk_crypto_host_stub.cpp)
    # Stub also lacks ECRECOVER recover -> add the recover-only abort stub.
    list(APPEND GUEST_SOURCES src/zisk_crypto_recover_stub.cpp)
elseif(SECP_BACKEND STREQUAL "libsecp256k1")
    # Provides both secp256k1_ecdsa_verify and _recover (via recover_compact).
    list(APPEND GUEST_SOURCES src/zisk_crypto_libsecp256k1.cpp)
elseif(SECP_BACKEND STREQUAL "zisk-libc")
    # secp256k1_ecdsa_verify comes from libziskc.a (linked below); lib-c has no
    # recover, so add the recover-only abort stub (verify-free, so it doesn't
    # shadow libziskc's archive verify symbol).
    list(APPEND GUEST_SOURCES src/zisk_crypto_recover_stub.cpp)
else()
    message(FATAL_ERROR "SECP_BACKEND must be zisk-libc | libsecp256k1 | stub (got ${SECP_BACKEND})")
endif()

# ----- EVM backend selection -------------------------------------------------
#
# The guest drives an EVM through the evmc2 interface (see ZiskStateDB::vm2_ /
# execute2), so the interpreter is swappable. `evmone` (default) uses the
# upstream interpreter via evmc2_create_evmone; `zevm` uses our hand-written one
# (cpp-guest/src/zevm) via evmc2_create_zevm. Both paths still link
# evmone::precompiles + evmone::state because precompile dispatch lives in the
# host/state layer.
set(EVM_BACKEND "evmone" CACHE STRING "EVM implementation: evmone | zevm")
set_property(CACHE EVM_BACKEND PROPERTY STRINGS evmone zevm)

add_executable(zisk_eth_guest ${GUEST_SOURCES})

target_include_directories(zisk_eth_guest PUBLIC include)
# evmone's baseline.hpp / vm.hpp (CodeAnalysis + the pre-analyzed execute()
# overload used by the analysis cache) live under lib/, not the public include/.
target_include_directories(zisk_eth_guest PRIVATE ${evmone_SOURCE_DIR}/lib)
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

if(SECP_BACKEND STREQUAL "libsecp256k1")
    find_path(SECP256K1_INCLUDE_DIR secp256k1.h
              HINTS /usr/local/include /usr/local/include2 /opt/homebrew/include)
    find_library(SECP256K1_LIBRARY secp256k1
              HINTS /usr/local/lib /opt/homebrew/lib)
    if(NOT SECP256K1_INCLUDE_DIR OR NOT SECP256K1_LIBRARY)
        message(FATAL_ERROR
            "SECP_BACKEND=libsecp256k1 but libsecp256k1 not found. "
            "brew install secp256k1.")
    endif()

    # The found include dir may be a chaotic shared directory (e.g.
    # /usr/local/include2 on this machine has hundreds of unrelated
    # headers that conflict with system files). Stage just
    # secp256k1.h into an isolated build-tree dir to avoid include-path
    # pollution.
    set(SECP256K1_STAGED_DIR ${CMAKE_BINARY_DIR}/secp256k1_include)
    file(MAKE_DIRECTORY ${SECP256K1_STAGED_DIR})
    configure_file(${SECP256K1_INCLUDE_DIR}/secp256k1.h
                   ${SECP256K1_STAGED_DIR}/secp256k1.h
                   COPYONLY)

    target_include_directories(zisk_eth_guest PRIVATE ${SECP256K1_STAGED_DIR})
    target_link_libraries(zisk_eth_guest PRIVATE ${SECP256K1_LIBRARY})
endif()

if(SECP_BACKEND STREQUAL "zisk-libc")
    if(APPLE)
        set(_HOST_PLATFORM darwin)
    elseif(UNIX)
        set(_HOST_PLATFORM linux)
    else()
        message(FATAL_ERROR
            "SECP_BACKEND=zisk-libc only supports macOS / Linux hosts.")
    endif()

    set(ZISKC_BUILD_DIR ${CMAKE_BINARY_DIR}/ziskc)
    set(ZISKC_LIBRARY   ${ZISKC_BUILD_DIR}/libziskc.a)
    add_custom_command(
        OUTPUT  ${ZISKC_LIBRARY}
        COMMAND bash ${CMAKE_SOURCE_DIR}/scripts/build-ziskc.sh
                     ${ZISK_LIBC_SRC}
                     ${ZISKC_BUILD_DIR}
                     ${_HOST_PLATFORM}
        DEPENDS ${ZISK_LIBC_SRC}/src/ec/ec.cpp  # canary; rebuild on any touch
        COMMENT "Building ZisK lib-c (libziskc.a) from ${ZISK_LIBC_SRC}"
        VERBATIM
    )
    add_custom_target(ziskc DEPENDS ${ZISKC_LIBRARY})
    add_dependencies(zisk_eth_guest ziskc)

    # GMP discovery — Homebrew on Intel macOS = /usr/local; Apple
    # Silicon = /opt/homebrew; Linux relies on the default search path.
    find_path(GMP_INCLUDE_DIR  gmpxx.h HINTS /usr/local/include /opt/homebrew/include)
    find_library(GMP_LIBRARY   gmp     HINTS /usr/local/lib     /opt/homebrew/lib)
    find_library(GMPXX_LIBRARY gmpxx   HINTS /usr/local/lib     /opt/homebrew/lib)
    if(NOT GMP_INCLUDE_DIR OR NOT GMP_LIBRARY OR NOT GMPXX_LIBRARY)
        message(FATAL_ERROR
            "SECP_BACKEND=zisk-libc but GMP not found. brew install gmp (macOS) "
            "or apt-get install libgmp-dev (Linux).")
    endif()

    target_include_directories(zisk_eth_guest PRIVATE ${GMP_INCLUDE_DIR})
    target_link_libraries(zisk_eth_guest PRIVATE
        ${ZISKC_LIBRARY}
        ${GMPXX_LIBRARY}
        ${GMP_LIBRARY})
endif()
