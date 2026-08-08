# memcmp.s — DMA-precompile memcmp thunk for the ZisK cpp-guest.
# Vendored from zisk/ziskos/entrypoint/src/dma/memcmp.s (the .attribute lines were
# dropped — our ASM is built -march=rv64ima_zicsr; see CMakeLists), then moved off
# upstream's deprecated marker spelling, see below.
#
# The `csrrs a0,0x814,a1` + `add x0,a0,a2` pattern lowers to the dma_memcmp
# precompile: memcmp(a=a0, b=a1, count=a2), result in a0.
#
# The result register must ride on the `csrrs` (rd), not on the `add`: the
# transpiler accepts both, but `add rd!=x0` is its DEPRECATED form and every run
# prints "DEPRECATED INSTRUCTION: dma_memcmp transpilation pattern" (see
# transpile_dma_memcpy_memcmp_pattern). Both forms lower to the same op with the
# same rd, so this is purely the current spelling.
#
# `csrrs a0, …` looks like it clobbers a0 before the `add` reads it, but the pair
# collapses into ONE zisk op that reads reg(dst)=a0 and reg(src)=a1 and only then
# stores the result into reg(rd)=a0 — as with every thunk here, the standalone
# RISC-V reading of these two instructions is not what executes.
        .section ".note.GNU-stack","",@progbits
        .text
        .globl  memcmp
        .p2align        4
        .type   memcmp,@function
memcmp:
        csrrs   a0, 0x814, a1  # Marker: result -> a0, src = a1
        add	x0,a0,a2       # dst = a0, count = a2
        ret

        .size memcmp, .-memcmp
        .section .text.hot,"ax",@progbits
