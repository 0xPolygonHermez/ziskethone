# memcmp.s — DMA-precompile memcmp thunk for the ZisK cpp-guest.
# Vendored verbatim from zisk/ziskos/entrypoint/src/dma/memcmp.s (the .attribute
# lines were dropped — our ASM is built -march=rv64ima_zicsr; see CMakeLists).
#
# The `csrs 0x814,b` + `add a0,a0,size` pattern lowers to the dma_xmemcmp
# precompile: memcmp(a=a0, b=a1, count=a2), result in a0.
        .section ".note.GNU-stack","",@progbits
        .text
        .globl  memcmp
        .p2align        4
        .type   memcmp,@function
memcmp:
        csrs    0x814, a1  # Marker: Write count (a2) to CSR 0x814
        add	a0,a0,a2
        ret

        .size memcmp, .-memcmp
        .section .text.hot,"ax",@progbits
