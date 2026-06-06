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
set(_ZISK_ARCH "-march=rv64ima_zicsr -mabi=lp64 -mcmodel=medany")
set(_ZISK_FREE "-fno-exceptions -fno-rtti -ffunction-sections -fdata-sections")

set(CMAKE_C_FLAGS_INIT   "${_ZISK_ARCH} ${_ZISK_FREE}")
set(CMAKE_CXX_FLAGS_INIT "${_ZISK_ARCH} ${_ZISK_FREE}")
set(CMAKE_ASM_FLAGS_INIT "${_ZISK_ARCH}")

# Don't look for host programs/libraries in the target sysroot.
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
