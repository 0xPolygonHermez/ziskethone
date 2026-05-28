#!/usr/bin/env bash
#
# Build the ZisK lib-c (libziskc.a) for the host so the cpp-guest can
# link a real `secp256k1_ecdsa_verify` instead of the aborting weak
# stub. Invoked by CMake when WITH_ZISK_LIBC=ON.
#
# Usage:
#   build-ziskc.sh <lib-c-src-dir> <output-dir> <platform>
#
# Where:
#   <lib-c-src-dir>   absolute path to /Users/.../zisk/lib-c/c
#   <output-dir>      where libziskc.a and obj/*.o land (CMAKE_BINARY_DIR/ziskc)
#   <platform>        'darwin' or 'linux' (drives NASM format flags)

set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: $0 <lib-c-src-dir> <output-dir> <darwin|linux>" >&2
    exit 1
fi

SRC="$1"
OUT="$2"
PLATFORM="$3"

# Separate the assembly and C++ output dirs so files like fec.asm and
# fec.cpp (which produce same-basename .o) don't clobber each other.
mkdir -p "$OUT/obj/asm" "$OUT/obj/cpp"

# NASM format + symbol-prefix + warning flags per platform.
#  -w-number-deprecated-hex silences the noisy "$DEADBEEF deprecated"
#  warnings from the auto-generated ffiasm files.
NASM_COMMON=(-w-number-deprecated-hex)
case "$PLATFORM" in
    darwin)
        # Mach-O 64 + macOS C symbol underscore prefix.
        NASM_FMT=(-fmacho64 --prefix _ "${NASM_COMMON[@]}")
        # macOS NASM rejects the trailing `.note.GNU-stack` section
        # the ffiasm files use to mark a non-executable stack — that's
        # Linux ELF only. Strip via sed before assembling.
        DARWIN_ASM_FILTER='/^section[[:space:]]+\.note\.GNU-stack/,$d'
        ;;
    linux)
        NASM_FMT=(-felf64 "${NASM_COMMON[@]}")
        DARWIN_ASM_FILTER=
        ;;
    *)
        echo "build-ziskc.sh: unsupported platform '$PLATFORM' (want darwin|linux)" >&2
        exit 1
        ;;
esac

# Allow-list: only the lib-c objects the cpp-guest actually needs
# (secp256k1_ecdsa_verify + its transitive math). The full lib-c
# library also has BLS12-381, BN254, secp256r1, etc., whose global
# constructors run at process startup and use x86-64 instructions
# (BMI2 / ADX) absent on some host CPUs — they'd crash before main().
# Limiting the build avoids that and shrinks libziskc.a to ~50 KB.
ASM_KEEP=(fec fnec)                           # secp256k1 base + scalar field
CPP_FFIASM_KEEP=(fec fnec)                    # C++ glue around the above
CPP_EC_KEEP=("$SRC/src/ec/ec.cpp")            # secp256k1_ecdsa_verify itself

# 1. Assemble the secp256k1 .asm files only.
for base in "${ASM_KEEP[@]}"; do
    asm="$SRC/src/ffiasm/${base}.asm"
    [[ -f "$asm" ]] || { echo "missing $asm" >&2; exit 1; }
    src="$asm"
    if [[ -n "$DARWIN_ASM_FILTER" ]]; then
        # Strip Linux-only `.note.GNU-stack` trailer for Mach-O builds.
        src="$OUT/obj/asm/${base}.macho.asm"
        sed -E "$DARWIN_ASM_FILTER" "$asm" > "$src"
    fi
    nasm "${NASM_FMT[@]}" "$src" -o "$OUT/obj/asm/${base}.o"
done

# 2. Compile the C++ glue.
#
# Force-include <sys/types.h> for `uint` (Sys V typedef the ffiasm
# headers use but don't include themselves). Suppress noisy deprecation
# warnings on stdlib (sprintf) and the GMP user-defined literals; these
# don't affect correctness and just bloat the build log.
CXX_INCLUDES=("-I$SRC/src")
[[ -d /usr/local/include ]]   && CXX_INCLUDES+=("-I/usr/local/include")
[[ -d /opt/homebrew/include ]] && CXX_INCLUDES+=("-I/opt/homebrew/include")
CXX_FLAGS=(-O3 -fPIC -std=c++17 -include sys/types.h
           -Wno-deprecated-declarations
           -Wno-deprecated-literal-operator
           -Wno-user-defined-literals)

compile_cpp() {
    local cpp="$1" base
    base=$(basename "$cpp" .cpp)
    clang++ "${CXX_FLAGS[@]}" "${CXX_INCLUDES[@]}" -c "$cpp" -o "$OUT/obj/cpp/${base}.o"
}

for base in "${CPP_FFIASM_KEEP[@]}"; do
    compile_cpp "$SRC/src/ffiasm/${base}.cpp"
done
for cpp in "${CPP_EC_KEEP[@]}"; do
    compile_cpp "$cpp"
done

# 3. Slim globals.cpp — define ONLY the two extern globals (`fec`,
#    `fnec`) that ec.cpp actually references. Skipping lib-c's own
#    globals.cpp because it instantiates BLS12-381 / secp256r1 / BN254
#    globals whose ctors crash here.
cat > "$OUT/obj/cpp/zeg_globals.cpp" <<'GLOBALS'
#include "ffiasm/fec.hpp"
#include "ffiasm/fnec.hpp"
RawFec  fec;
RawFnec fnec;
GLOBALS
compile_cpp "$OUT/obj/cpp/zeg_globals.cpp"

# 4. Archive.
ar rcs "$OUT/libziskc.a" "$OUT/obj/asm"/*.o "$OUT/obj/cpp"/*.o

n_asm=$(ls "$OUT/obj/asm"/*.o | wc -l)
n_cpp=$(ls "$OUT/obj/cpp"/*.o | wc -l)
echo "built $OUT/libziskc.a (${n_asm// /} asm + ${n_cpp// /} cpp objects)"
