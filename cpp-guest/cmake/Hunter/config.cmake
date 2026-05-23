# Hunter package configs for the dependencies pulled in by evmone.
# Mirrors the relevant entries from evmone's own cmake/Hunter/config.cmake;
# we only need the runtime deps (test/bench packages are skipped because
# EVMONE_TESTING / EVMONE_FUZZING are OFF).

include(hunter_cmake_args)

hunter_config(
    intx
    VERSION 0.15.0
    URL https://github.com/chfast/intx/archive/v0.15.0.tar.gz
    SHA1 571b3f4c5a7b09135755720b478bc03f9d7ba7bb
)
