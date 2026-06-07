# memcpy.s — DMA-precompile memcpy thunk for the ZisK cpp-guest.
# Vendored verbatim from zisk/ziskos/entrypoint/src/dma/memcpy.s (the .attribute
# lines were dropped — our ASM is built -march=rv64ima_zicsr; see CMakeLists).
#
# The transpiler (riscv2zisk) recognizes the `csrs 0x813,src` + `add x0,dst,size`
# instruction pattern and lowers it to a single dma_xmemcpy precompile op:
# memcpy(dst=a0, src=a1, count=a2). Handles any size/alignment internally.
        .section ".note.GNU-stack","",@progbits
        .text
        .globl  memcpy
        .p2align        4
        .type   memcpy,@function
memcpy:
        csrs    0x813, a1                  # Marker: Write count (a2) to CSR 0x813
        add	x0,a0,a2
        ret

        .size memcpy, .-memcpy
        .section .text.hot,"ax",@progbits
