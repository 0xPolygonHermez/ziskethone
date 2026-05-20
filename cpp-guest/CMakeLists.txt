cmake_minimum_required(VERSION 3.20)
project(zisk_eth_guest CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# NOTE: For an actual ZisK build, the toolchain must target the ZisK RISC-V
# zkVM (riscv64ima-zisk-zkvm-elf). C++ guest support in ZisK is still
# experimental and lives outside this CMakeLists for now.
# This file builds a *host-side* sanity binary that can read the binary input
# file produced by `rust-input-gen` — useful for format validation during
# development.

add_executable(guest_host_sanity
    src/main.cpp
)

target_include_directories(guest_host_sanity PUBLIC include)
target_compile_options(guest_host_sanity PRIVATE -Wall -Wextra -Wpedantic)
