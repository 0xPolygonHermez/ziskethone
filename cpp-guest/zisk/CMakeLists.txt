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
# bls/kzg pull blst+c-kzg (asm); modexp pulls std::pmr. bn254 (ecadd/ecmul) is
# replaced by our ZisK-accelerated bn254_eip196.cpp. All are excluded here and
# provided by the ZISK_SUPPORT wrapper TUs below.
list(FILTER PRECOMP_SRC EXCLUDE REGEX "/bls\\.cpp$|/kzg\\.cpp$|/modexp\\.cpp$|/bn254\\.cpp$|/secp256r1\\.cpp$|/sha256\\.cpp$|/blake2b\\.cpp$")
# bn254 pairing lives in a subdirectory (ECPAIRING precompile); we provide our own
# evmmax::bn254::pairing_check, so exclude evmone's software pairing too.
file(GLOB PAIRING_SRC   ${EVMONE_SRC}/lib/evmone_precompiles/pairing/*/*.cpp)
list(FILTER PAIRING_SRC EXCLUDE REGEX "/pairing/bn254/")
# Keccak: instead of evmone's software keccak.c, compile our drop-in that
# routes the Keccak-f[1600] permutation through the ZisK precompile (CSR 0x800).
# Same public symbol (ethash_keccak256), so every Keccak call site is accelerated.
set(PRECOMP_C  ${CMAKE_CURRENT_SOURCE_DIR}/keccak_zisk.cpp ${CMAKE_CURRENT_SOURCE_DIR}/zkvm_stubs.c)
# Only the precompile dispatch from test/state (not the json/state machinery).
set(STATE_SRC  ${EVMONE_SRC}/test/state/precompiles.cpp)

# DMA mem* thunks: memcpy/memmove/memcmp/memset routed through the ZisK DMA
# precompiles (CSR 0x813/0x814/0x816). These replace runtime.cpp's software mem*,
# so EVERY target that compiles runtime.cpp must also link DMA_SRC (otherwise any
# memcpy/memset reference — incl. ones the compiler synthesizes from STL/intx —
# is undefined). The transpiler lowers the csrs+add/addi pattern to a single
# accelerated op; see dma/*.s.
set(DMA_SRC
  ${CMAKE_CURRENT_SOURCE_DIR}/dma/memcpy.s
  ${CMAKE_CURRENT_SOURCE_DIR}/dma/memmove.s
  ${CMAKE_CURRENT_SOURCE_DIR}/dma/memcmp.s
  ${CMAKE_CURRENT_SOURCE_DIR}/dma/memset.s)

# ZisK runtime / freestanding support.
set(ZISK_SUPPORT
  ${CMAKE_CURRENT_SOURCE_DIR}/_start.s
  ${CMAKE_CURRENT_SOURCE_DIR}/runtime.cpp
  ${DMA_SRC}
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
  # EIP-2537 BLS12-381 precompiles (0x0b–0x11) via the bls12_381/ port.
  ${CMAKE_CURRENT_SOURCE_DIR}/bls12_381_eip2537.cpp
  # alt_bn128 / BN254 precompiles (ecAdd 0x06, ecMul 0x07, ecPairing 0x08) via the
  # bn254/ port on the ZisK bn254 precompiles + fcall hints.
  ${CMAKE_CURRENT_SOURCE_DIR}/bn254_eip196.cpp
  # secp256r1 / P-256 ECDSA precompile (p256verify 0x100) via the secp256r1/ port
  # on the ZisK secp256r1 precompiles (0x817/0x818) + fn_inv fcall.
  ${CMAKE_CURRENT_SOURCE_DIR}/secp256r1_p256.cpp
  # SHA-256 precompile (0x02) + KZG/EIP-7685 hashing: drop-in evmone::crypto::sha256
  # routing the compression through the ZisK sha256f precompile (CSR 0x805).
  ${CMAKE_CURRENT_SOURCE_DIR}/sha256_zisk.cpp
  # BLAKE2 precompile (0x09, EIP-152 F compression): drop-in
  # evmone::crypto::blake2b_compress routing each round through the ZisK
  # blake2b_round precompile (CSR 0x819).
  ${CMAKE_CURRENT_SOURCE_DIR}/blake2b_zisk.cpp
  # Stubs for evmone's create_*_tracer factories so tracing.cpp (and its iostream
  # deps) can be dropped from the build — the guest never enables a tracer.
  ${CMAKE_CURRENT_SOURCE_DIR}/tracer_stubs.cpp
)

add_executable(zisk_eth_guest.elf
  ${GUEST_SRC} ${EVMONE_CORE} ${EVMMAX_SRC} ${PRECOMP_SRC} ${PAIRING_SRC}
  ${PRECOMP_C} ${STATE_SRC} ${ZISK_SUPPORT})

# secp256k1 backend: precompiles+fcalls by default; software baseline when ON.
option(ZEG_SECP256K1_SW "Use the software secp256k1 baseline (no accelerators)" OFF)

# zeg::bswap64 defaults to a zero-shortcut swap that uses inline-asm `rev8`
# (now that the guest march includes Zbb) for the nonzero path, keeping the
# branch GCC would otherwise silently fold away (see include/zeg/bswap.hpp for
# why plain __builtin_bswap64 loses that shortcut). ZEG_BSWAP_BUILTIN swaps in
# the plain builtin instead, purely for A/B step-count comparison against the
# shortcut-preserving default — expect it to lose on zero-heavy blocks.
option(ZEG_BSWAP_BUILTIN "Use plain __builtin_bswap64 (no zero-shortcut) instead of the default shortcut-preserving rev8" OFF)

# EF zkVM-accelerator C ABI swaps (semicolon list e.g. "ZKVM_KECCAK;ZKVM_SHA256;ZKVM_SECP256K1").
# Each token guards a drop-in call to the standard zkvm_* symbol, which elf2rom
# redirects to the native .zisk routine. Empty by default (no behavior change).
set(ZKVM_ABI "" CACHE STRING "EF ABI crypto swaps to enable in the guest")

target_compile_definitions(zisk_eth_guest.elf PRIVATE
  ZEG_ZISK
  ${ZKVM_ABI}
  $<$<STREQUAL:${EVM_BACKEND},zevm>:USE_ZEVM>
  $<$<BOOL:${ZEG_SECP256K1_SW}>:ZEG_SECP256K1_SW>
  $<$<BOOL:${ZEG_BSWAP_BUILTIN}>:ZEG_BSWAP_BUILTIN>
  PROJECT_VERSION="0.21.0")          # normally injected by evmone's CMake
target_compile_options(zisk_eth_guest.elf PRIVATE $<$<CONFIG:Release>:${ZEG_GUEST_OPT_LIST}>)
target_link_options(zisk_eth_guest.elf PRIVATE $<$<CONFIG:Release>:${ZEG_GUEST_OPT_LIST}>)
# runtime.cpp's calloc no longer zero-fills (the bump arena is fresh, ZisK-zero
# RAM) and realloc copies via the DMA memcpy. -fno-builtin keeps that an
# out-of-line call to the dma/*.s memcpy symbol rather than an inlined byte loop;
# -fno-tree-loop-distribute-patterns keeps any other runtime.cpp loops (str*) from
# being rewritten into mem* idioms.
set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/runtime.cpp
  TARGET_DIRECTORY zisk_eth_guest.elf PROPERTIES
  COMPILE_OPTIONS "-fno-tree-loop-distribute-patterns;-fno-builtin")

# ECADD (0x06) reaches the generic evmmax::ecc::add_affine template inside
# precompiles.cpp; force-include our explicit BN254 specialization so the dispatch
# routes through the accelerated G1 add (definition in bn254_eip196.cpp).
set_source_files_properties(${STATE_SRC} TARGET_DIRECTORY zisk_eth_guest.elf PROPERTIES
  COMPILE_OPTIONS "-include;${CMAKE_CURRENT_SOURCE_DIR}/bn254/add_affine_spec.hpp")

target_include_directories(zisk_eth_guest.elf PRIVATE
  ${GUEST_ROOT}/include
  ${GUEST_ROOT}/src/zevm                # zevm headers (no-op for evmone backend)
  ${CMAKE_CURRENT_SOURCE_DIR}           # zeg::bi backend: bigint/backend.hpp
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
  ${DMA_SRC}
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
  ${DMA_SRC}
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
  ${DMA_SRC}
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

# --- modexp_bench.elf: RSA-2048 large-exponent modexp benchmark (cost profiling) ---
add_executable(modexp_bench.elf
  ${CMAKE_CURRENT_SOURCE_DIR}/bigint/test/bench_modexp_zisk.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/_start.s
  ${CMAKE_CURRENT_SOURCE_DIR}/runtime.cpp
  ${DMA_SRC}
  ${CMAKE_CURRENT_SOURCE_DIR}/stdcxx_stubs.cpp)
target_compile_definitions(modexp_bench.elf PRIVATE ZEG_ZISK)
target_compile_options(modexp_bench.elf PRIVATE $<$<CONFIG:Release>:-Os>)
target_include_directories(modexp_bench.elf PRIVATE ${GUEST_ROOT}/include)
target_link_options(modexp_bench.elf PRIVATE
  -T ${CMAKE_CURRENT_SOURCE_DIR}/zisk.ld -nostdlib -nostartfiles -Wl,--gc-sections)
set_target_properties(modexp_bench.elf PROPERTIES LINK_DEPENDS
  ${CMAKE_CURRENT_SOURCE_DIR}/zisk.ld)
add_custom_command(TARGET modexp_bench.elf POST_BUILD
  COMMAND ${CMAKE_OBJCOPY}
    --remove-section .eh_frame --remove-section .eh_frame_hdr
    --remove-section '.gcc_except_table*' --remove-section .comment
    --remove-section .riscv.attributes
    $<TARGET_FILE:modexp_bench.elf> $<TARGET_FILE:modexp_bench.elf>
  COMMENT "Stripping ZisK-incompatible sections")

# --- ecrecover_bench.elf: secp256k1 ECRECOVER selftest + GLV cost benchmark ---
add_executable(ecrecover_bench.elf
  ${CMAKE_CURRENT_SOURCE_DIR}/bigint/test/bench_ecrecover_zisk.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/_start.s
  ${CMAKE_CURRENT_SOURCE_DIR}/runtime.cpp
  ${DMA_SRC}
  ${CMAKE_CURRENT_SOURCE_DIR}/stdcxx_stubs.cpp)
target_compile_definitions(ecrecover_bench.elf PRIVATE ZEG_ZISK)
target_compile_options(ecrecover_bench.elf PRIVATE $<$<CONFIG:Release>:-Os>)
target_include_directories(ecrecover_bench.elf PRIVATE ${GUEST_ROOT}/include)
target_link_options(ecrecover_bench.elf PRIVATE
  -T ${CMAKE_CURRENT_SOURCE_DIR}/zisk.ld -nostdlib -nostartfiles -Wl,--gc-sections)
set_target_properties(ecrecover_bench.elf PROPERTIES LINK_DEPENDS
  ${CMAKE_CURRENT_SOURCE_DIR}/zisk.ld)
add_custom_command(TARGET ecrecover_bench.elf POST_BUILD
  COMMAND ${CMAKE_OBJCOPY}
    --remove-section .eh_frame --remove-section .eh_frame_hdr
    --remove-section '.gcc_except_table*' --remove-section .comment
    --remove-section .riscv.attributes
    $<TARGET_FILE:ecrecover_bench.elf> $<TARGET_FILE:ecrecover_bench.elf>
  COMMENT "Stripping ZisK-incompatible sections")

# --- bls2537_selftest.elf: on-emulator self-test of the EIP-2537 layers ---
# Exercises mul/msm, pairing_check and map-to-curve (SWU + isogeny + cofactor)
# on the precompile/fcall backend. See bls12_381/test/selftest_eip2537_zisk.cpp.
add_executable(bls2537_selftest.elf
  ${CMAKE_CURRENT_SOURCE_DIR}/bls12_381/test/selftest_eip2537_zisk.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/_start.s
  ${CMAKE_CURRENT_SOURCE_DIR}/runtime.cpp
  ${DMA_SRC}
  ${CMAKE_CURRENT_SOURCE_DIR}/stdcxx_stubs.cpp)
target_compile_definitions(bls2537_selftest.elf PRIVATE ZEG_ZISK)
target_compile_options(bls2537_selftest.elf PRIVATE $<$<CONFIG:Release>:-Os>)
target_include_directories(bls2537_selftest.elf PRIVATE ${GUEST_ROOT}/include)
target_link_options(bls2537_selftest.elf PRIVATE
  -T ${CMAKE_CURRENT_SOURCE_DIR}/zisk.ld -nostdlib -nostartfiles -Wl,--gc-sections)
set_target_properties(bls2537_selftest.elf PROPERTIES LINK_DEPENDS
  ${CMAKE_CURRENT_SOURCE_DIR}/zisk.ld)
add_custom_command(TARGET bls2537_selftest.elf POST_BUILD
  COMMAND ${CMAKE_OBJCOPY}
    --remove-section .eh_frame --remove-section .eh_frame_hdr
    --remove-section '.gcc_except_table*' --remove-section .comment
    --remove-section .riscv.attributes
    $<TARGET_FILE:bls2537_selftest.elf> $<TARGET_FILE:bls2537_selftest.elf>
  COMMENT "Stripping ZisK-incompatible sections")

# --- bn254_selftest.elf: on-emulator self-test of the BN254 (alt_bn128) layers ---
# Exercises ecAdd/ecMul (curve precompiles 0x806/0x807) + ecPairing (Fp2 complex
# precompiles, fp_inv/fp2_inv/twist-line fcalls) on the precompile/fcall backend.
add_executable(bn254_selftest.elf
  ${CMAKE_CURRENT_SOURCE_DIR}/bn254/test/selftest_eip196_zisk.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/_start.s
  ${CMAKE_CURRENT_SOURCE_DIR}/runtime.cpp
  ${DMA_SRC}
  ${CMAKE_CURRENT_SOURCE_DIR}/stdcxx_stubs.cpp)
target_compile_definitions(bn254_selftest.elf PRIVATE ZEG_ZISK)
target_compile_options(bn254_selftest.elf PRIVATE $<$<CONFIG:Release>:-Os>)
target_include_directories(bn254_selftest.elf PRIVATE ${GUEST_ROOT}/include)
target_link_options(bn254_selftest.elf PRIVATE
  -T ${CMAKE_CURRENT_SOURCE_DIR}/zisk.ld -nostdlib -nostartfiles -Wl,--gc-sections)
set_target_properties(bn254_selftest.elf PROPERTIES LINK_DEPENDS
  ${CMAKE_CURRENT_SOURCE_DIR}/zisk.ld)
add_custom_command(TARGET bn254_selftest.elf POST_BUILD
  COMMAND ${CMAKE_OBJCOPY}
    --remove-section .eh_frame --remove-section .eh_frame_hdr
    --remove-section '.gcc_except_table*' --remove-section .comment
    --remove-section .riscv.attributes
    $<TARGET_FILE:bn254_selftest.elf> $<TARGET_FILE:bn254_selftest.elf>
  COMMENT "Stripping ZisK-incompatible sections")

# --- p256_selftest.elf: on-emulator self-test of the secp256r1 (P-256) layer ---
# Exercises ecdsa_verify (arith256_mod + secp256r1 add/dbl precompiles 0x817/0x818
# + fn_inv/msb fcalls) on valid + tampered + boundary vectors.
add_executable(p256_selftest.elf
  ${CMAKE_CURRENT_SOURCE_DIR}/secp256r1/test/selftest_p256_zisk.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/_start.s
  ${CMAKE_CURRENT_SOURCE_DIR}/runtime.cpp
  ${DMA_SRC}
  ${CMAKE_CURRENT_SOURCE_DIR}/stdcxx_stubs.cpp)
target_compile_definitions(p256_selftest.elf PRIVATE ZEG_ZISK)
target_compile_options(p256_selftest.elf PRIVATE $<$<CONFIG:Release>:-Os>)
target_include_directories(p256_selftest.elf PRIVATE ${GUEST_ROOT}/include)
target_link_options(p256_selftest.elf PRIVATE
  -T ${CMAKE_CURRENT_SOURCE_DIR}/zisk.ld -nostdlib -nostartfiles -Wl,--gc-sections)
set_target_properties(p256_selftest.elf PROPERTIES LINK_DEPENDS
  ${CMAKE_CURRENT_SOURCE_DIR}/zisk.ld)
add_custom_command(TARGET p256_selftest.elf POST_BUILD
  COMMAND ${CMAKE_OBJCOPY}
    --remove-section .eh_frame --remove-section .eh_frame_hdr
    --remove-section '.gcc_except_table*' --remove-section .comment
    --remove-section .riscv.attributes
    $<TARGET_FILE:p256_selftest.elf> $<TARGET_FILE:p256_selftest.elf>
  COMMENT "Stripping ZisK-incompatible sections")

# --- sha256_selftest.elf: on-emulator self-test of the SHA-256 layer ---
# Hashes known inputs (incl. multi-block/padding-boundary) via the sha256f
# precompile (0x805) and checks the FIPS 180-4 KAT digests.
add_executable(sha256_selftest.elf
  ${CMAKE_CURRENT_SOURCE_DIR}/sha256/test/selftest_sha256_zisk.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/_start.s
  ${CMAKE_CURRENT_SOURCE_DIR}/runtime.cpp
  ${DMA_SRC}
  ${CMAKE_CURRENT_SOURCE_DIR}/stdcxx_stubs.cpp)
target_compile_definitions(sha256_selftest.elf PRIVATE ZEG_ZISK)
target_compile_options(sha256_selftest.elf PRIVATE $<$<CONFIG:Release>:-Os>)
target_include_directories(sha256_selftest.elf PRIVATE ${GUEST_ROOT}/include)
target_link_options(sha256_selftest.elf PRIVATE
  -T ${CMAKE_CURRENT_SOURCE_DIR}/zisk.ld -nostdlib -nostartfiles -Wl,--gc-sections)
set_target_properties(sha256_selftest.elf PROPERTIES LINK_DEPENDS
  ${CMAKE_CURRENT_SOURCE_DIR}/zisk.ld)
add_custom_command(TARGET sha256_selftest.elf POST_BUILD
  COMMAND ${CMAKE_OBJCOPY}
    --remove-section .eh_frame --remove-section .eh_frame_hdr
    --remove-section '.gcc_except_table*' --remove-section .comment
    --remove-section .riscv.attributes
    $<TARGET_FILE:sha256_selftest.elf> $<TARGET_FILE:sha256_selftest.elf>
  COMMENT "Stripping ZisK-incompatible sections")

# --- blake2_selftest.elf: on-emulator self-test of the BLAKE2b layer ---
# Runs the EIP-152 F compression (rounds 0/1/12, "abc" vector) via the
# blake2b_round precompile (0x819) and checks the working-state outputs.
add_executable(blake2_selftest.elf
  ${CMAKE_CURRENT_SOURCE_DIR}/blake2b/test/selftest_blake2_zisk.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/_start.s
  ${CMAKE_CURRENT_SOURCE_DIR}/runtime.cpp
  ${DMA_SRC}
  ${CMAKE_CURRENT_SOURCE_DIR}/stdcxx_stubs.cpp)
target_compile_definitions(blake2_selftest.elf PRIVATE ZEG_ZISK)
target_compile_options(blake2_selftest.elf PRIVATE $<$<CONFIG:Release>:-Os>)
target_include_directories(blake2_selftest.elf PRIVATE ${GUEST_ROOT}/include)
target_link_options(blake2_selftest.elf PRIVATE
  -T ${CMAKE_CURRENT_SOURCE_DIR}/zisk.ld -nostdlib -nostartfiles -Wl,--gc-sections)
set_target_properties(blake2_selftest.elf PROPERTIES LINK_DEPENDS
  ${CMAKE_CURRENT_SOURCE_DIR}/zisk.ld)
add_custom_command(TARGET blake2_selftest.elf POST_BUILD
  COMMAND ${CMAKE_OBJCOPY}
    --remove-section .eh_frame --remove-section .eh_frame_hdr
    --remove-section '.gcc_except_table*' --remove-section .comment
    --remove-section .riscv.attributes
    $<TARGET_FILE:blake2_selftest.elf> $<TARGET_FILE:blake2_selftest.elf>
  COMMENT "Stripping ZisK-incompatible sections")
