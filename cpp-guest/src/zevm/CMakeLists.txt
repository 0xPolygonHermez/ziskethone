# zevm — hand-written EVM, drop-in replacement for evmone at the evmc C ABI.
#
# Depends only on evmc's header-only types (evmc/evmc.h, evmc/utils.h), not on
# evmone's interpreter. The evmc headers come from the FetchContent'd evmone
# source tree; the parent CMakeLists exposes evmone_SOURCE_DIR.

add_library(zevm STATIC
    zevm.cpp
    evm_state.cpp
    evm_mem.cpp
    instructions.cpp
)

target_include_directories(zevm
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${evmone_SOURCE_DIR}/evmc/include
)

target_compile_features(zevm PUBLIC cxx_std_20)
target_compile_options(zevm PRIVATE -Wall -Wextra)

# Keep the zeg::bi backend selection consistent with the rest of the guest:
# when the parent build targets the ZisK zkVM it defines ZEG_ZISK, which flips
# zeg/bigint/backend.hpp from the portable software path to the ZisK precompile
# path. zevm doesn't use that header yet, but real arithmetic opcodes will.
if(DEFINED ZEG_ZISK_BACKEND AND ZEG_ZISK_BACKEND)
    target_compile_definitions(zevm PUBLIC ZEG_ZISK)
endif()
