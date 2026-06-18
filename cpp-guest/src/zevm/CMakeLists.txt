# zevm — hand-written EVM, drop-in replacement for evmone at the evmc2 boundary.
#
# Depends on the evmc2 interface (zeg/evmc2.h, which only pulls evmc's
# header-only types) — not on evmone's interpreter — plus the header-only ZisK
# 256-bit backend (zeg::bi) for arithmetic opcodes. The evmc headers come from
# the FetchContent'd evmone source tree; the parent CMakeLists exposes
# evmone_SOURCE_DIR.

# The opcode handlers are inline headers (instructions/*.inl.hpp) included by
# zevm.cpp, which holds the per-fork dispatch switch — so there is no per-category
# translation unit and no runtime dispatch table.
add_library(zevm STATIC
    zevm.cpp
    evm_state.cpp
    evm_mem.cpp
)

target_include_directories(zevm
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${evmone_SOURCE_DIR}/evmc/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../../include  # zeg/evmc2.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../zisk      # zeg::bi 256-bit backend (bigint/backend.hpp)
)

# KECCAK256 (and future hash precompiles) use zeg::keccak256_bytes32, which wraps
# evmone's keccak (ethash::keccak256). evmone_precompiles is the precompiles
# library — not the interpreter — and carries the <evmone_precompiles/...> header
# include path plus the keccak symbol.
target_link_libraries(zevm PUBLIC evmone_precompiles)

target_compile_features(zevm PUBLIC cxx_std_20)
target_compile_options(zevm PRIVATE -Wall -Wextra)

# Keep the zeg::bi backend selection consistent with the rest of the guest:
# when the parent build targets the ZisK zkVM it defines ZEG_ZISK, which flips
# zeg/bigint/backend.hpp from the portable software path to the ZisK precompile
# path. zevm doesn't use that header yet, but real arithmetic opcodes will.
if(DEFINED ZEG_ZISK_BACKEND AND ZEG_ZISK_BACKEND)
    target_compile_definitions(zevm PUBLIC ZEG_ZISK)
endif()
