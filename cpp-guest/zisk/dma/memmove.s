# memmove.s — DMA-precompile memmove thunk for the ZisK cpp-guest.
# Vendored verbatim from zisk/ziskos/entrypoint/src/dma/memmove.s (the .attribute
# lines were dropped — our ASM is built -march=rv64ima_zicsr; see CMakeLists).
#
# memmove aliases to the SAME CSR 0x813 (dma_xmemcpy) as memcpy. This is correct:
# the emulator's Mem::memcpy detects src/dst overlap and copies via a temp buffer,
# honoring memmove semantics.
        .section ".note.GNU-stack","",@progbits
        .text
        .globl  memmove
        .p2align        4
        .type   memmove,@function
memmove:
        csrs    0x813, a1                  # Marker: Write count (a2) to CSR 0x813
        add	x0,a0,a2
        ret
        .size memmove, .-memmove
        .section .text.hot,"ax",@progbits
