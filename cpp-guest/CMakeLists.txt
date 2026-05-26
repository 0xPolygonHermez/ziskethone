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

# ----- guest executable ------------------------------------------------------
#
# NOTE: For an actual ZisK build, the toolchain must target the ZisK RISC-V
# zkVM (riscv64ima-zisk-zkvm-elf). C++ guest support in ZisK is still
# experimental and lives outside this CMakeLists for now.
#
# evmone v0.21.0 absorbed evmc into the same library, so a single `evmone`
# link target gives us both the EVM and the `evmc::Host` interface that
# ZiskStateDB implements.

add_executable(zisk_eth_guest
    src/main.cpp
    src/fatal.cpp
    src/accounts.cpp
    src/block_header.cpp
    src/bloom.cpp
    src/consensus_info.cpp
    src/contracts.cpp
    src/create_address.cpp
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
    src/zisk_crypto_host_stub.cpp
    src/zisk_state_db.cpp
)

target_include_directories(zisk_eth_guest PUBLIC include)
target_compile_options(zisk_eth_guest PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(zisk_eth_guest PRIVATE evmone evmone::precompiles)
