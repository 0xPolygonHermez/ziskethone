# toolchain.cmake — CMake cross-toolchain for the ZisK RISC-V zkVM target.
#
# Bare-metal rv64ima + Zicsr, freestanding (-nostdlib). Pass to CMake with
#   -DCMAKE_TOOLCHAIN_FILE=<this file>
# (the zisk/CMakeLists.txt sets the rest: linker script, sources, defines).

set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR riscv64)

# Auto-detect the bare-metal RISC-V g++ prefix (override with -DZISK_CROSS=...).
if(NOT ZISK_CROSS)
  foreach(_p riscv-none-elf- riscv64-unknown-elf- riscv64-elf-)
    find_program(_gxx ${_p}g++)
    if(_gxx)
      set(ZISK_CROSS ${_p})
      break()
    endif()
  endforeach()
endif()
if(NOT ZISK_CROSS)
  message(FATAL_ERROR "No RISC-V bare-metal toolchain found (riscv-none-elf-/riscv64-unknown-elf-/riscv64-elf-).")
endif()

set(CMAKE_C_COMPILER   ${ZISK_CROSS}gcc)
set(CMAKE_CXX_COMPILER ${ZISK_CROSS}g++)
set(CMAKE_ASM_COMPILER ${ZISK_CROSS}gcc)
set(CMAKE_OBJCOPY      ${ZISK_CROSS}objcopy CACHE FILEPATH "objcopy")

# Bare-metal: no test executable can be linked during compiler checks.
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

# NOTE: no -ffreestanding. It sets __STDC_HOSTED__=0 and libstdc++ headers
# (vector/unordered_map/variant — which the guest leans on) refuse to compile.
# We stay "hosted" for the headers and instead drop the runtime at link time
# (-nostdlib) + supply the referenced symbols in runtime.cpp.
#
# +zbb_zbs: RISC-V bit-manipulation, supported by the pinned zisk toolchain
# (pre-develop-1.2.0-alpha) since the merged feature/zbkb_extension work. Added
# deliberately narrow, not the full B extension (no zba/zbkb/zbkc/zbkx/zbc) —
# the zisk riscv2zisk transpiler maps most Zbb instructions (rol, clz, rev8,
# ...) to multi-op software decompositions of comparable or worse cost than
# the base-ISA sequences GCC already emits without the extension (verified by
# reading the transpiler's own per-op cost table). The one clear, verified win
# is Zbb's min/minu/max/maxu: these reuse the pre-existing native
# Min/Max/Minu/Maxu zisk ops (the same ones backing RV64A's amomin/amomax,
# already in our base ISA) at a flat single-op cost — GCC folds `a < b ? a : b`
# ternaries straight into a `minu`/`maxu` instruction once zbb is enabled, vs.
# the 4-instruction compare+branch+cmov sequence it emits today. zbs rides
# along for the rest of Zbb's decode table and costs nothing extra since none
# of the code here currently compiles to its instructions without deliberate
# opt-in (see zeg/bswap.hpp's ZEG_BSWAP_BUILTIN switch).
#
# zba (sh1add/sh2add/sh3add/add.uw/slli.uw) is deliberately EXCLUDED, for two
# reasons verified on a live mainnet block via ziskemu: (1) its transpiler
# decomposition is a wash-to-slightly-worse vs. the base-ISA shift+add GCC
# already emits (+13,435 steps, +0.007%, on top of zbb_zbs alone — measured
# with a ziskemu built with `--features riscv2zisk/zba`, the workspace has no
# feature that forwards to it, see below); (2) a *stock* `cargo build --bin
# ziskemu` doesn't compile Zba support in at all — it's gated behind a Cargo
# feature (`zba`/`zba_native` on the `riscv2zisk` crate, default off, and
# `emulator/Cargo.toml` — the crate ziskemu itself lives in — doesn't forward
# it) — so any zba instruction reaching a stock ziskemu panics the
# transpiler ("found invalid riscv_instruction.inst_name=sh3add").
#
# Overridable (e.g. -DZISK_MARCH=rv64ima_zicsr for an A/B baseline without the
# B extension, or to add zba/zbkb/zbkc/zbkx/zbc for further experiments —
# ziskemu needs rebuilding with the matching --features for the latter three).
set(ZISK_MARCH "rv64ima_zicsr_zbb_zbs" CACHE STRING "Guest -march string (without the rv64/-march= prefix)")
set(_ZISK_ARCH "-march=${ZISK_MARCH} -mabi=lp64 -mcmodel=medany")
set(_ZISK_FREE "-fno-exceptions -fno-rtti -ffunction-sections -fdata-sections")

set(CMAKE_C_FLAGS_INIT   "${_ZISK_ARCH} ${_ZISK_FREE}")
set(CMAKE_CXX_FLAGS_INIT "${_ZISK_ARCH} ${_ZISK_FREE}")
set(CMAKE_ASM_FLAGS_INIT "${_ZISK_ARCH}")

# Don't look for host programs/libraries in the target sysroot.
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
