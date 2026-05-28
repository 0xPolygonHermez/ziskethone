.section .text.init,"ax",@progbits
.global _start
.type _start, @function
_start:
    .option push
    .option norelax
    la gp, _global_pointer
    .option pop
    la sp, _init_stack_top

    /* Run C++ static constructors before main(). Each entry in
     * .init_array is a function pointer; call them in order.
     * s0/s1 are callee-saved per RISC-V ABI, so the called ctors
     * preserve them across the loop. */
    la s0, __init_array_start
    la s1, __init_array_end
.Linit_loop:
    beq s0, s1, .Linit_done
    ld t0, 0(s0)
    addi s0, s0, 8
    jalr ra, t0
    j .Linit_loop
.Linit_done:

    call main
    csrr t0, marchid
    li   t1, 0xFFFEEEE
    beq  t0, t1, 1f
    li   t0, 0x100000
    li   t1, 0x5555
    sw   t1, 0(t0)
    j    2f
1:  li   a7, 93
    ecall
2:  j    2b
