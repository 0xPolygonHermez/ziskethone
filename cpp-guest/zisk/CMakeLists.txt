# CMakeLists.txt — standalone ZisK (RISC-V zkVM) build of the cpp-guest.
#
# This is DELIBERATELY separate from ../CMakeLists.txt. The host build drives
# evmone through Hunter + evmone's Cable toolchain (cxx17-pic, GoogleTest, …),
# all of which assume a hosted compiler and force PIC — incompatible with the
# freestanding `-nostdlib -mcmodel=medany` link ZisK needs. evmone's compiled
# footprint here is small and Hunter-free (intx/evmc are header-only), so we
# just compile the sources we need with the cross toolchain.
#
# Configure with:
#   cmake -S cpp-guest/zisk -B cpp-guest/zisk/build \
#         -DCMAKE_TOOLCHAIN_FILE=cpp-guest/zisk/toolchain.cmake \
#         -DCMAKE_BUILD_TYPE=Release
#   cmake --build cpp-guest/zisk/build
# Produces cpp-guest/zisk/build/zisk_eth_guest.elf (ready for ziskemu).

cmake_minimum_required(VERSION 3.22)
project(zisk_eth_guest_zkvm CXX C ASM)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(GUEST_ROOT  ${CMAKE_CURRENT_SOURCE_DIR}/..)        # cpp-guest/

# --- locate the evmone source already downloaded by the host build ----------
# (FetchContent_Populate(evmone) in ../CMakeLists.txt → ../build*/_deps/evmone-src)
if(NOT EVMONE_SRC)
  foreach(_b build build-stub build-debug)
    if(EXISTS ${GUEST_ROOT}/${_b}/_deps/evmone-src/lib/evmone/vm.cpp)
      set(EVMONE_SRC ${GUEST_ROOT}/${_b}/_deps/evmone-src)
      break()
    endif()
  endforeach()
endif()
if(NOT EVMONE_SRC)
  message(FATAL_ERROR "evmone source not found. Run the host build once "
    "(cmake -S cpp-guest -B cpp-guest/build) to populate _deps, or pass -DEVMONE_SRC=...")
endif()
message(STATUS "evmone source: ${EVMONE_SRC}")

# --- locate intx headers (Hunter install dir from the host build) -----------
if(NOT INTX_INCLUDE)
  file(GLOB _intx_hits "$ENV{HOME}/.hunter/_Base/*/*/*/Install/include/intx/intx.hpp")
  if(_intx_hits)
    list(GET _intx_hits 0 _intx_hpp)
    get_filename_component(INTX_INCLUDE ${_intx_hpp} DIRECTORY)
    get_filename_component(INTX_INCLUDE ${INTX_INCLUDE} DIRECTORY)  # strip /intx
  endif()
endif()
if(NOT INTX_INCLUDE)
  message(FATAL_ERROR "intx headers not found under ~/.hunter; pass -DINTX_INCLUDE=...")
endif()
message(STATUS "intx include: ${INTX_INCLUDE}")

# --- source sets ------------------------------------------------------------
# Guest sources (exclude host-only crypto backends; main.cpp etc. are dual-mode).
file(GLOB GUEST_SRC ${GUEST_ROOT}/src/*.cpp)
list(FILTER GUEST_SRC EXCLUDE REGEX "zisk_crypto_host_stub|zisk_crypto_libsecp256k1")

# evmone interpreter + modular-arith + precompiles (minus the heavy bls/kzg TUs).
file(GLOB EVMONE_CORE   ${EVMONE_SRC}/lib/evmone/*.cpp)
# cpu_check.cpp is x86-only (__builtin_cpu_supports). tracing.cpp stays in (the
# guest never enables tracing, but vm.cpp references its factories); its
# std::ostream dependencies are satisfied by stdcxx_stubs.cpp.
list(FILTER EVMONE_CORE EXCLUDE REGEX "/cpu_check\\.cpp$")
file(GLOB EVMMAX_SRC    ${EVMONE_SRC}/lib/evmmax/*.cpp)
file(GLOB PRECOMP_SRC   ${EVMONE_SRC}/lib/evmone_precompiles/*.cpp)
# bls/kzg pull blst+c-kzg (asm); modexp pulls std::pmr. All three are stubbed
# (see precompile_stubs.cpp) — fine until a block needs those precompiles.
list(FILTER PRECOMP_SRC EXCLUDE REGEX "/bls\\.cpp$|/kzg\\.cpp$|/modexp\\.cpp$")
# bn254 pairing lives in a subdirectory (ECPAIRING precompile).
file(GLOB PAIRING_SRC   ${EVMONE_SRC}/lib/evmone_precompiles/pairing/*/*.cpp)
# Keccak: instead of evmone's software keccak.c, compile our drop-in that
# routes the Keccak-f[1600] permutation through the ZisK precompile (CSR 0x800).
# Same public symbol (ethash_keccak256), so every Keccak call site is accelerated.
set(PRECOMP_C  ${CMAKE_CURRENT_SOURCE_DIR}/keccak_zisk.cpp)
# Only the precompile dispatch from test/state (not the json/state machinery).
set(STATE_SRC  ${EVMONE_SRC}/test/state/precompiles.cpp)

# ZisK runtime / freestanding support.
set(ZISK_SUPPORT
  ${CMAKE_CURRENT_SOURCE_DIR}/_start.s
  ${CMAKE_CURRENT_SOURCE_DIR}/runtime.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/compiler_rt.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/stdcxx_stubs.cpp
  # secp256k1 ECDSA. Default: ZisK precompiles + fcall hints. With
  # -DZEG_SECP256K1_SW=ON: portable software baseline (same source, same result).
  ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1.cpp
  # KZG point-eval (EIP-4844) via the self-contained BLS12-381 pairing port
  # (bls12_381/*.hpp) on the ZisK precompiles + fcall hints.
  ${CMAKE_CURRENT_SOURCE_DIR}/bls12_381_kzg.cpp
  # MODEXP (EIP-198) via the self-contained arbitrary-precision bigint port
  # (bigint/*.hpp) on the ZisK arith256/add256 precompiles + fcall hints.
  ${CMAKE_CURRENT_SOURCE_DIR}/modexp_zisk.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/precompile_stubs.cpp
)

add_executable(zisk_eth_guest.elf
  ${GUEST_SRC} ${EVMONE_CORE} ${EVMMAX_SRC} ${PRECOMP_SRC} ${PAIRING_SRC}
  ${PRECOMP_C} ${STATE_SRC} ${ZISK_SUPPORT})

# secp256k1 backend: precompiles+fcalls by default; software baseline when ON.
option(ZEG_SECP256K1_SW "Use the software secp256k1 baseline (no accelerators)" OFF)

target_compile_definitions(zisk_eth_guest.elf PRIVATE
  ZEG_ZISK
  $<$<BOOL:${ZEG_SECP256K1_SW}>:ZEG_SECP256K1_SW>
  PROJECT_VERSION="0.21.0")          # normally injected by evmone's CMake
target_compile_options(zisk_eth_guest.elf PRIVATE $<$<CONFIG:Release>:-Os>)

target_include_directories(zisk_eth_guest.elf PRIVATE
  ${GUEST_ROOT}/include
  ${EVMONE_SRC}/include
  ${EVMONE_SRC}/evmc/include
  ${EVMONE_SRC}                       # for <lib/...> and <test/state/...>
  ${EVMONE_SRC}/lib
  ${EVMONE_SRC}/lib/evmone_precompiles
  ${INTX_INCLUDE})

# Freestanding link: our linker script + no stdlib + dead-strip.
target_link_options(zisk_eth_guest.elf PRIVATE
  -T ${CMAKE_CURRENT_SOURCE_DIR}/zisk.ld
  -nostdlib -nostartfiles
  -Wl,--gc-sections)
set_target_properties(zisk_eth_guest.elf PROPERTIES LINK_DEPENDS
  ${CMAKE_CURRENT_SOURCE_DIR}/zisk.ld)

# Strip sections the ZisK loader rejects.
add_custom_command(TARGET zisk_eth_guest.elf POST_BUILD
  COMMAND ${CMAKE_OBJCOPY}
    --remove-section .eh_frame --remove-section .eh_frame_hdr
    --remove-section '.gcc_except_table*' --remove-section .comment
    --remove-section .riscv.attributes
    $<TARGET_FILE:zisk_eth_guest.elf> $<TARGET_FILE:zisk_eth_guest.elf>
  COMMENT "Stripping ZisK-incompatible sections")

# --- bls_selftest.elf: on-emulator self-test of the BLS12-381 ZisK backend ---
# Lean ELF (no evmone) that exercises the precompile/fcall paths; run under
# ziskemu to validate/debug the accelerated BLS layers. See bls12_381/test/.
add_executable(bls_selftest.elf
  ${CMAKE_CURRENT_SOURCE_DIR}/bls12_381/test/selftest_zisk.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/_start.s
  ${CMAKE_CURRENT_SOURCE_DIR}/runtime.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/compiler_rt.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/stdcxx_stubs.cpp)
target_compile_definitions(bls_selftest.elf PRIVATE ZEG_ZISK)
target_compile_options(bls_selftest.elf PRIVATE $<$<CONFIG:Release>:-Os>)
target_include_directories(bls_selftest.elf PRIVATE ${GUEST_ROOT}/include)
target_link_options(bls_selftest.elf PRIVATE
  -T ${CMAKE_CURRENT_SOURCE_DIR}/zisk.ld -nostdlib -nostartfiles -Wl,--gc-sections)
set_target_properties(bls_selftest.elf PROPERTIES LINK_DEPENDS
  ${CMAKE_CURRENT_SOURCE_DIR}/zisk.ld)
add_custom_command(TARGET bls_selftest.elf POST_BUILD
  COMMAND ${CMAKE_OBJCOPY}
    --remove-section .eh_frame --remove-section .eh_frame_hdr
    --remove-section '.gcc_except_table*' --remove-section .comment
    --remove-section .riscv.attributes
    $<TARGET_FILE:bls_selftest.elf> $<TARGET_FILE:bls_selftest.elf>
  COMMENT "Stripping ZisK-incompatible sections")

# --- bigint_selftest.elf: on-emulator self-test of the MODEXP backend ---
# Exercises the arith256 (0x801) precompile + bin_decomp/bigint_div fcalls.
add_executable(bigint_selftest.elf
  ${CMAKE_CURRENT_SOURCE_DIR}/bigint/test/selftest_backend_zisk.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/_start.s
  ${CMAKE_CURRENT_SOURCE_DIR}/runtime.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/compiler_rt.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/stdcxx_stubs.cpp)
target_compile_definitions(bigint_selftest.elf PRIVATE ZEG_ZISK)
target_compile_options(bigint_selftest.elf PRIVATE $<$<CONFIG:Release>:-Os>)
target_include_directories(bigint_selftest.elf PRIVATE ${GUEST_ROOT}/include)
target_link_options(bigint_selftest.elf PRIVATE
  -T ${CMAKE_CURRENT_SOURCE_DIR}/zisk.ld -nostdlib -nostartfiles -Wl,--gc-sections)
set_target_properties(bigint_selftest.elf PROPERTIES LINK_DEPENDS
  ${CMAKE_CURRENT_SOURCE_DIR}/zisk.ld)
add_custom_command(TARGET bigint_selftest.elf POST_BUILD
  COMMAND ${CMAKE_OBJCOPY}
    --remove-section .eh_frame --remove-section .eh_frame_hdr
    --remove-section '.gcc_except_table*' --remove-section .comment
    --remove-section .riscv.attributes
    $<TARGET_FILE:bigint_selftest.elf> $<TARGET_FILE:bigint_selftest.elf>
  COMMENT "Stripping ZisK-incompatible sections")

# --- modexp_selftest.elf: on-emulator EIP-198 modexp on the ZisK backend ---
add_executable(modexp_selftest.elf
  ${CMAKE_CURRENT_SOURCE_DIR}/bigint/test/selftest_modexp_zisk.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/_start.s
  ${CMAKE_CURRENT_SOURCE_DIR}/runtime.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/compiler_rt.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/stdcxx_stubs.cpp)
target_compile_definitions(modexp_selftest.elf PRIVATE ZEG_ZISK)
target_compile_options(modexp_selftest.elf PRIVATE $<$<CONFIG:Release>:-Os>)
target_include_directories(modexp_selftest.elf PRIVATE ${GUEST_ROOT}/include)
target_link_options(modexp_selftest.elf PRIVATE
  -T ${CMAKE_CURRENT_SOURCE_DIR}/zisk.ld -nostdlib -nostartfiles -Wl,--gc-sections)
set_target_properties(modexp_selftest.elf PROPERTIES LINK_DEPENDS
  ${CMAKE_CURRENT_SOURCE_DIR}/zisk.ld)
add_custom_command(TARGET modexp_selftest.elf POST_BUILD
  COMMAND ${CMAKE_OBJCOPY}
    --remove-section .eh_frame --remove-section .eh_frame_hdr
    --remove-section '.gcc_except_table*' --remove-section .comment
    --remove-section .riscv.attributes
    $<TARGET_FILE:modexp_selftest.elf> $<TARGET_FILE:modexp_selftest.elf>
  COMMENT "Stripping ZisK-incompatible sections")
