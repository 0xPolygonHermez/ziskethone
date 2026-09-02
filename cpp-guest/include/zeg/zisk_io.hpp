// zisk_io.hpp — ZisK zkVM memory-mapped I/O for the cpp-guest.
//
// Only compiled into the ZisK build (ZEG_ZISK). Mirrors the fixed-address ABI
// the ziskemu emulator and ZisK hardware expose (see ../../hello-zisk-c/src/zisk.h):
//
//   INPUT  at 0x40000000 : [0..8) reserved, [8..16) u64 LE length, [16..) payload
//   OUTPUT at 0xA0410000 : array of u32 public-output slots (= SYS_ADDR + SYS_SIZE)
//   UART   at 0xA0400200 : write a byte to print it (debug)  (= SYS_ADDR + 0x200)
//
// OUTPUT/UART track the ZisK memory map in `zisk core/src/mem.rs` as of the
// pinned pre-develop-1.2.0-alpha toolchain: RAM_ADDR=0xa0000000, and as of
// commit 004dcadfc ("Move stack to the bottom of the RAM") SYS_ADDR is now
// genuinely RAM_ADDR+STACK_SIZE(0x400000)=0xa0400000 (matches zisk.ld's
// `.stack_data` reservation at the bottom of RAM). SYS_SIZE=0x10000, so
// OUTPUT_ADDR=SYS_ADDR+SYS_SIZE=0xa0410000, UART_ADDR=SYS_ADDR+0x200=
// 0xa0400200.
//
// History, so this doesn't look like a silent flip-flop: on the PRIOR pin
// (pre-develop-1.0.0-alfa), SYS_ADDR==RAM_ADDR (no stack offset existed
// yet) — a premature "correction" to these same 0xA0410000/0xA0400200
// values landed here anyway, silently writing the public output past where
// ziskemu/hardware ever read it (proving completed, step/cost looked
// normal, output was all-zero). That was reverted in commit c0f705c, back
// to 0xA0010000/0xA0000200. The pre-develop-1.2.0-alpha upgrade is what
// makes the offset real, so these addresses move forward again here —
// this time verified by actually running the ZisK-target ELF (not just
// the host build) through ziskemu against a live block and checking the
// emitted hash, not just step counts.
//
// The host (rust-input-gen) writes the block container starting with the
// `ZEG0` magic; to feed it to ziskemu it is framed as [u64 LE len][payload],
// so payload == the container and `read_input()` returns a pointer to its
// first byte (the magic).

#pragma once

#include <cstddef>
#include <cstdint>

namespace zeg::zisk {

struct Input {
    const uint8_t *ptr;  // first byte of the payload (the ZEG0 container)
    uint64_t       len;  // payload length in bytes
};

// Read the framed input region. Layout at INPUT_ADDR: [0..8) reserved,
// [8..16) u64 LE length, [16..) payload.
inline Input read_input() {
    const volatile uint64_t *base =
        reinterpret_cast<const volatile uint64_t *>(0x40000000ULL + 8);
    Input in;
    in.len = base[0];
    in.ptr = reinterpret_cast<const uint8_t *>(
        reinterpret_cast<uintptr_t>(base + 1));
    return in;
}

// Write a u32 public-output slot (proof-visible).
inline void set_output_u32(unsigned slot, uint32_t value) {
    reinterpret_cast<volatile uint32_t *>(0xA0410000ULL)[slot] = value;
}

// Emit a 32-byte value (e.g. the block hash) as 8 u32 slots. Each word is
// packed little-endian so that, once the (little-endian) RISC-V store lands in
// memory, the bytes sit in their original order — that is how ziskemu's
// byte-wise output reader (get_output_8) and the native guest's hex dump read
// them, so the public output is the 32 bytes in order.
inline void set_output_bytes32(const uint8_t bytes[32]) {
    for (unsigned i = 0; i < 8; ++i) {
        uint32_t w = (uint32_t(bytes[4*i]))        |
                     (uint32_t(bytes[4*i+1]) <<  8) |
                     (uint32_t(bytes[4*i+2]) << 16) |
                     (uint32_t(bytes[4*i+3]) << 24);
        set_output_u32(i, w);
    }
}

// UART debug: write one byte to the console.
inline void uart_putc(char c) {
    *reinterpret_cast<volatile unsigned char *>(0xA0400200) =
        static_cast<unsigned char>(c);
}

// UART debug: write a NUL-terminated string.
inline void uart_puts(const char *s) {
    for (; *s != '\0'; ++s) {
        uart_putc(*s);
    }
}

// UART debug: write `len` bytes as lowercase hex, no prefix.
inline void uart_put_hex(const uint8_t *bytes, unsigned len) {
    static const char kHexDigits[] = "0123456789abcdef";
    for (unsigned i = 0; i < len; ++i) {
        uart_putc(kHexDigits[bytes[i] >> 4]);
        uart_putc(kHexDigits[bytes[i] & 0x0f]);
    }
}

} // namespace zeg::zisk
