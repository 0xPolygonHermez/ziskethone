#!/usr/bin/env bash
#
# Build the patched cross-compiler that gives the guest -mzisk-dma.
#
# Run once. It downloads GCC's own sources, applies
# 0001-riscv-zisk-dma-lowering.patch, builds the compiler and installs it into a
# fixed prefix. Every later run sees the compiler already there and exits in a
# second, so it is safe to call from a build script or CI step.
#
# There is no fork of GCC anywhere: the patch in this directory is the whole
# delta, applied to a pristine upstream tarball.
#
# Only the compiler proper is built (`make all-gcc`) — no libgcc, no newlib, no
# libstdc++, which is what makes it ~10 minutes instead of an hour. The guest
# links -nostdlib -nostartfiles with no libraries, so the only things still
# needed from a normal toolchain are the C++ *headers* and the assembler and
# linker; those are taken from the xPack toolchain by symlink, which is why its
# version has to match exactly.
#
# Usage:
#     cpp-guest/patches/gcc/build-toolchain.sh [--force]
#
# Then put the printed directory first on PATH and configure the guest with
# -DZEG_ZISK_DMA=ON.

set -euo pipefail

GCC_VERSION=14.3.0
PATCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATCH="$PATCH_DIR/0001-riscv-zisk-dma-lowering.patch"

# Installed next to the xPack toolchains, and named for what it is, so that
# having it on PATH is an explicit choice rather than a surprise.
PREFIX="${ZISK_DMA_GCC_PREFIX:-$HOME/.local/xPacks/zisk-dma-gcc-$GCC_VERSION}"
XPACK="${ZISK_XPACK_DIR:-$HOME/.local/xPacks/xpack-riscv-none-elf-gcc-$GCC_VERSION-1}"
BUILD_DIR="${ZISK_DMA_GCC_BUILD_DIR:-${TMPDIR:-/tmp}/zisk-dma-gcc-build}"

say() { printf '==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- already? ---
supports_flag() {
    [ -x "$1" ] && echo 'int main(){}' |
        "$1" -x c++ -march=rv64ima_zicsr -mabi=lp64 -mzisk-dma -fsyntax-only - 2>/dev/null
}

if [ "${1:-}" != "--force" ] && supports_flag "$PREFIX/bin/riscv-none-elf-g++"; then
    say "already installed: $PREFIX"
    "$PREFIX/bin/riscv-none-elf-g++" --version | head -1
    echo
    echo "export PATH=\"$PREFIX/bin:\$PATH\""
    exit 0
fi

# ------------------------------------------------------------ requirements ---
[ -f "$PATCH" ] || die "patch not found: $PATCH"
[ -x "$XPACK/bin/riscv-none-elf-as" ] ||
    die "xPack $GCC_VERSION not found at $XPACK (set ZISK_XPACK_DIR). Its C++ headers and
       binutils are reused, so the version must match GCC $GCC_VERSION exactly."

# GCC 14's bundled libcody does not build with a host compiler newer than ~14
# (u8"" literals became char8_t), which is a build-time failure with a very
# unhelpful message. Pick an older host compiler when one is around.
HOST_CC=${CC:-}; HOST_CXX=${CXX:-}
if [ -z "$HOST_CXX" ]; then
    for v in 13 12 11; do
        if command -v "g++-$v" >/dev/null && command -v "gcc-$v" >/dev/null; then
            HOST_CXX="g++-$v"; HOST_CC="gcc-$v"; break
        fi
    done
fi
[ -n "$HOST_CXX" ] || die "no g++-13/12/11 found for the host build; install one or set CXX/CC"
say "host compiler: $HOST_CXX"

for tool in curl tar make; do
    command -v "$tool" >/dev/null || die "missing required tool: $tool"
done

# -------------------------------------------------------------- fetch/patch --
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

TARBALL="gcc-$GCC_VERSION.tar.xz"
if [ ! -f "$TARBALL" ]; then
    say "downloading GCC $GCC_VERSION (~95 MB)"
    curl -fL --retry 3 -o "$TARBALL.part" \
        "https://ftp.gnu.org/gnu/gcc/gcc-$GCC_VERSION/$TARBALL"
    mv "$TARBALL.part" "$TARBALL"
fi

SRC="$BUILD_DIR/gcc-$GCC_VERSION"
if [ ! -d "$SRC" ]; then
    say "extracting"
    tar xf "$TARBALL"
    say "downloading prerequisites (gmp/mpfr/mpc/isl)"
    (cd "$SRC" && ./contrib/download_prerequisites >/dev/null)
fi

if ! (cd "$SRC" && patch -p1 -R --dry-run -s -f < "$PATCH" >/dev/null 2>&1); then
    say "applying $(basename "$PATCH")"
    (cd "$SRC" && patch -p1 < "$PATCH")
else
    say "patch already applied"
fi

# --------------------------------------------------------------- configure ---
say "configuring (compiler only)"
rm -rf "$BUILD_DIR/build" && mkdir -p "$BUILD_DIR/build"
cd "$BUILD_DIR/build"
CC="$HOST_CC" CXX="$HOST_CXX" "$SRC/configure" \
    --target=riscv-none-elf \
    --prefix="$PREFIX" \
    --with-arch=rv64ima_zicsr --with-abi=lp64 \
    --disable-multilib --disable-nls --disable-shared --disable-threads \
    --disable-libssp --disable-libquadmath --disable-libgomp --disable-libatomic \
    --enable-languages=c,c++ --without-headers --with-newlib >configure.log 2>&1 ||
    { tail -20 configure.log; die "configure failed (see $BUILD_DIR/build/configure.log)"; }

say "building (~10 min on $(nproc) cores)"
make all-gcc -j"$(nproc)" >build.log 2>&1 ||
    { grep -E "error" build.log | head -10; die "build failed (see $BUILD_DIR/build/build.log)"; }
make install-gcc >install.log 2>&1 || die "install failed"

# ------------------------------------------------- graft xPack's target side --
# Headers, and the assembler/linker the driver invokes. Versions match, so the
# driver finds everything where it expects it.
say "linking xPack's target side into $PREFIX"
rm -rf "$PREFIX/riscv-none-elf"
ln -s "$XPACK/riscv-none-elf" "$PREFIX/riscv-none-elf"
for t in as ld ar ranlib nm objcopy objdump strip readelf; do
    [ -e "$XPACK/bin/riscv-none-elf-$t" ] &&
        ln -sf "$XPACK/bin/riscv-none-elf-$t" "$PREFIX/bin/"
done

# -------------------------------------------------------------------- check --
supports_flag "$PREFIX/bin/riscv-none-elf-g++" || die "built compiler does not accept -mzisk-dma"

# And that the flag actually lowers something, not just parses.
tmp=$(mktemp -d)
cat > "$tmp/t.cpp" <<'EOF'
#include <cstring>
extern void sink(void*);
void f(void* d, const void* s) { std::memcpy(d, s, 32); sink(d); }
EOF
"$PREFIX/bin/riscv-none-elf-g++" -O2 -march=rv64ima_zicsr -mabi=lp64 -mcmodel=medany \
    -mzisk-dma -S -o "$tmp/t.s" "$tmp/t.cpp"
grep -q "csrs.*0x813" "$tmp/t.s" || die "the flag parses but emits no DMA marker"
rm -rf "$tmp"

say "done: $PREFIX"
"$PREFIX/bin/riscv-none-elf-g++" --version | head -1
echo
echo "Put it first on PATH and turn the flag on:"
echo "    export PATH=\"$PREFIX/bin:\$PATH\""
echo "    cmake -S cpp-guest/zisk -B cpp-guest/zisk/build-dma \\"
echo "          -DCMAKE_TOOLCHAIN_FILE=\$PWD/cpp-guest/zisk/toolchain.cmake \\"
echo "          -DCMAKE_BUILD_TYPE=Release -DZEG_ZISK_DMA=ON"
