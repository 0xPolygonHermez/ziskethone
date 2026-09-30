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

# Guest optimization flags (Release). ZisK proving cost is ∝ the number of
# *executed* instructions, where every instruction costs the same — so unlike a
# real CPU, the goal is to minimize instruction count, not pipeline throughput.
# `-mtune=size` tunes GCC's codegen toward exactly that and is the dominant win
# here (measured -13% block cost on its own); `-funroll-loops` + the inlining
# `--param`s add a few more % by cutting call/loop overhead on hot paths
# (evmone dispatch, keccak, MPT). Measured on block 25271907: 20.996B -> 17.64B
# (-16%, steps -21.6%), identical output, verified across a dozen blocks.
#
# NOT used: -flto (only +1.8% over this set but its LTO codegen overran the RAM
# ceiling 0xc0000000 on some flag combos -> emulator OOB; too fragile for a
# prover) and -fipa-pta (measurably worse here, and slow to compile).
#
# Overridable, e.g. -DZEG_GUEST_OPT="-O3".
set(ZEG_GUEST_OPT "-O3 -mtune=size -funroll-loops --param=max-inline-insns-single=1600 --param=max-inline-insns-auto=533 --param=inline-unit-growth=266 --param=max-inline-recursive-depth=6 --param=max-completely-peeled-insns=400 --param=large-function-growth=280 --param=large-unit-insns=30000 -fno-schedule-insns -fno-schedule-insns2 -fno-jump-tables" CACHE STRING "Guest Release optimization flags")
separate_arguments(ZEG_GUEST_OPT_LIST UNIX_COMMAND "${ZEG_GUEST_OPT}")

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

# --- EVM backend: evmone (default, upstream) | zevm (hand-written) -----------
# zevm swaps the evmc2 VM only: zisk_state_db.cpp picks evmc2_create_zevm over
# evmc2_create_evmone under USE_ZEVM. evmone's precompiles/state still build (the
# host dispatches ECRECOVER/MODEXP/… through them); just the interpreter changes.
# zevm's 256-bit math compiles against the ZisK zeg::bi backend (ZEG_ZISK), and
# its KECCAK256 resolves to the same accelerated ethash_keccak256 (keccak_zisk).
# evmone is the default: its baseline interpreter is cheaper on ZisK (zevm pays
# per-op byteswaps + gas/stack checks). Measured on two live mainnet blocks
# (step counts via ziskemu, both backends verified against the RPC block hash):
#   block 25605549 (515 txs): evmone 190,110,154 steps vs zevm 199,344,080 (+4.9%)
#   block 25606586 (224 txs): evmone 237,860,530 steps vs zevm 261,389,688 (+9.9%)
# The gap narrows with the guest march's Zbb/Zbs bit-manipulation extensions
# (see toolchain.cmake): zevm gains slightly more from them (7.7-9.0% fewer
# steps) than evmone does (6.1-6.5%), since zevm's hand-rolled byteswaps give
# the compiler more to fold into rev8/minu/maxu — narrowing evmone's edge to
# +3.5%/+6.5% on the same two blocks. Gap size looks block-dependent (denser
# contract-call activity should widen it further, per the above).
set(EVM_BACKEND "evmone" CACHE STRING "EVM implementation: evmone | zevm")
if(EVM_BACKEND STREQUAL "zevm")
  list(FILTER GUEST_SRC EXCLUDE REGEX "/evmc2_evmone\\.cpp$")
  file(GLOB ZEVM_SRC ${GUEST_ROOT}/src/zevm/*.cpp ${GUEST_ROOT}/src/zevm/instructions/*.cpp)

  # zevm dispatches with a 140-case switch, so -fno-jump-tables (in
  # ZEG_GUEST_OPT, where it is worth -1.58% area to evmone) turns it into a
  # binary tree of comparisons: 7-8 branches per opcode instead of one indexed
  # jump. Measured on block 25701329, that tree costs 47% of the dispatch loop —
  # `bne`+`bltu`+`bgeu`+`li` alone are 89.6M of its 189M steps — and the whole
  # backend +3.42% area. evmone never notices the flag because its computed goto
  # is a hand-written label table, not a switch GCC has to lower.
  #
  # So the flag is right globally and wrong for this one file: put the jump
  # table back where the switch lives.
  set_source_files_properties(${GUEST_ROOT}/src/zevm/zevm.cpp
                              PROPERTIES COMPILE_OPTIONS "-fjump-tables")
  list(APPEND GUEST_SRC ${ZEVM_SRC})
endif()
message(STATUS "EVM backend: ${EVM_BACKEND}")

# evmone interpreter + modular-arith + precompiles (minus the heavy bls/kzg TUs).
file(GLOB EVMONE_CORE   ${EVMONE_SRC}/lib/evmone/*.cpp)
# cpu_check.cpp is x86-only (__builtin_cpu_supports). tracing.cpp is excluded — the
# guest never enables tracing; vm.cpp's set_option only references the three
# create_*_tracer factories, which we stub (tracer_stubs.cpp) to drop the whole
# evmone tracer + its iostream dependency from the link.
list(FILTER EVMONE_CORE EXCLUDE REGEX "/cpu_check\\.cpp$|/tracing\\.cpp$")
file(GLOB EVMMAX_SRC    ${EVMONE_SRC}/lib/evmmax/*.cpp)
file(GLOB PRECOMP_SRC   ${EVMONE_SRC}/lib/evmone_precompiles/*.cpp)
# Every precompile family with an EF zkVM accelerator is excluded here and provided
# by a ZISK_SUPPORT wrapper TU below, which calls the zkvm_* function instead.
list(FILTER PRECOMP_SRC EXCLUDE REGEX "/bls\\.cpp$|/kzg\\.cpp$|/modexp\\.cpp$|/bn254\\.cpp$|/secp256r1\\.cpp$|/sha256\\.cpp$|/blake2b\\.cpp$|/ripemd160\\.cpp$")
# bn254 pairing lives in a subdirectory (ECPAIRING precompile); we provide our own
# evmmax::bn254::pairing_check, so exclude evmone's software pairing too.
file(GLOB PAIRING_SRC   ${EVMONE_SRC}/lib/evmone_precompiles/pairing/*/*.cpp)
list(FILTER PAIRING_SRC EXCLUDE REGEX "/pairing/bn254/")
# Keccak: instead of evmone's software keccak.c, compile our drop-in that calls
# zkvm_keccak256. Same public symbol (ethash_keccak256), so every Keccak call site
# goes through the ABI.
# zkvm_calls.s: the EF ABI zkvm_* functions as zkvmcall thunks. Each is
# `csrs <id>, x0; ret`, which the transpiler turns into a jump to the native .zisk
# routine; running the guest needs ziskemu/cargo-zisk built with --features ziskasm.
set(PRECOMP_C  ${CMAKE_CURRENT_SOURCE_DIR}/keccak_zisk.cpp ${CMAKE_CURRENT_SOURCE_DIR}/zkvm_calls.s)
# Only the precompile dispatch from test/state (not the json/state machinery).
set(STATE_SRC  ${EVMONE_SRC}/test/state/precompiles.cpp)

# ZisK runtime / freestanding support.
set(ZISK_SUPPORT
  ${CMAKE_CURRENT_SOURCE_DIR}/_start.s
  ${CMAKE_CURRENT_SOURCE_DIR}/runtime.cpp
  # The freestanding libc memory functions — every memcpy/memmove/memcmp/memset the
  # compiler or STL/intx calls — on the ZisK memory ABI's DMA ops (zkvm_mem.s,
  # vendored), plus the run-time-fill memset that zkvm_mem.h falls back to.
  ${CMAKE_CURRENT_SOURCE_DIR}/zkvm_mem.s
  ${CMAKE_CURRENT_SOURCE_DIR}/stdcxx_stubs.cpp
  # The precompile families, each a drop-in for evmone's symbol that calls the EF
  # zkVM accelerator ABI (zkvm_accelerators.h):
  #   secp256k1 ECDSA recover (tx senders, EIP-7702 signers, ECRECOVER 0x01),
  #   KZG point evaluation (0x0a), MODEXP (0x05), EIP-2537 BLS12-381 (0x0b–0x11),
  #   BN254 ecAdd/ecMul/ecPairing (0x06–0x08), P-256 verify (0x100), SHA-256
  #   (0x02, plus the KZG and EIP-7685 hashes), RIPEMD-160 (0x03), BLAKE2 F (0x09).
  ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/bls12_381_kzg.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/modexp_zisk.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/bls12_381_eip2537.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/bn254_eip196.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/secp256r1_p256.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/sha256_zisk.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/ripemd160_zisk.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/blake2b_zisk.cpp
  # Stubs for evmone's create_*_tracer factories so tracing.cpp (and its iostream
  # deps) can be dropped from the build — the guest never enables a tracer.
  ${CMAKE_CURRENT_SOURCE_DIR}/tracer_stubs.cpp
)

add_executable(zisk_eth_guest.elf
  ${GUEST_SRC} ${EVMONE_CORE} ${EVMMAX_SRC} ${PRECOMP_SRC} ${PAIRING_SRC}
  ${PRECOMP_C} ${STATE_SRC} ${ZISK_SUPPORT})

# zeg::bswap64 defaults to plain __builtin_bswap64, which the guest march's Zbb
# lowers to a single unconditional `rev8`. Turning this OFF selects the older
# inline-asm variant that guards `rev8` with a zero shortcut; that only paid back
# when `rev8` cost 13 zisk ops, and it now loses on both counts — see
# include/zeg/bswap.hpp for the measurement. Kept as an A/B knob, not a tuning
# recommendation.
option(ZEG_BSWAP_BUILTIN "Use plain __builtin_bswap64 (Zbb lowers it to one rev8); OFF selects the legacy zero-shortcut inline asm" ON)

# JUMPDEST analysis: by default both backends offload it to the jump_dest_bitmap
# precompile (through zkvm_evm_jumpdest_bitmap, one op per contract — see evm/jump_dest_bitmap.hpp,
# evmone patch 05 and zevm's build_jumpdest_bitset). ON restores the software
# byte walk in both, for A/B step counts and as a fallback if the precompile is
# unavailable in the pinned toolchain.
option(ZEG_JUMPDEST_SW "Use the software JUMPDEST analysis (no jump_dest_bitmap precompile)" OFF)

target_compile_definitions(zisk_eth_guest.elf PRIVATE
  ZEG_ZISK
  $<$<STREQUAL:${EVM_BACKEND},zevm>:USE_ZEVM>
  $<$<BOOL:${ZEG_BSWAP_BUILTIN}>:ZEG_BSWAP_BUILTIN>
  $<$<BOOL:${ZEG_JUMPDEST_SW}>:ZEG_JUMPDEST_SW>
  PROJECT_VERSION="0.21.0")          # normally injected by evmone's CMake
target_compile_options(zisk_eth_guest.elf PRIVATE $<$<CONFIG:Release>:${ZEG_GUEST_OPT_LIST}>)
target_link_options(zisk_eth_guest.elf PRIVATE $<$<CONFIG:Release>:${ZEG_GUEST_OPT_LIST}>)
# runtime.cpp's calloc no longer zero-fills (the bump arena is fresh, ZisK-zero
# RAM) and realloc copies via memcpy. -fno-builtin keeps that an out-of-line call
# to the memcpy symbol (zkvm_mem.s) rather than an inlined byte loop;
# -fno-tree-loop-distribute-patterns keeps any other runtime.cpp loops (str*) from
# being rewritten into mem* idioms.
set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/runtime.cpp
  TARGET_DIRECTORY zisk_eth_guest.elf PROPERTIES
  COMPILE_OPTIONS "-fno-tree-loop-distribute-patterns;-fno-builtin")

# ECADD (0x06) reaches the generic evmmax::ecc::add_affine template inside
# precompiles.cpp; force-include our explicit BN254 specialization so the dispatch
# routes through zkvm_bn254_g1_add (definition in bn254_eip196.cpp).
set_source_files_properties(${STATE_SRC} TARGET_DIRECTORY zisk_eth_guest.elf PROPERTIES
  COMPILE_OPTIONS "-include;${CMAKE_CURRENT_SOURCE_DIR}/bn254/add_affine_spec.hpp")

target_include_directories(zisk_eth_guest.elf PRIVATE
  ${GUEST_ROOT}/include
  ${GUEST_ROOT}/src/zevm                # zevm headers (no-op for evmone backend)
  ${CMAKE_CURRENT_SOURCE_DIR}           # zkvm_*.h ABI headers, bls12_381/zkvm_marshal.hpp
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
