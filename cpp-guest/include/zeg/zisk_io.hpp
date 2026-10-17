// zisk_io.hpp — ZisK zkVM I/O for the cpp-guest.
//
// Only compiled into the ZisK build (ZEG_ZISK). The private input and the public
// output go through the EF zkVM I/O ABI (zkvm_io.h: read_input / write_output),
// zkvmcall thunks that the transpiler turns into jumps to the ZisK library's
// routines; the guest no longer reads or writes their fixed addresses itself.
// Debug printing still writes the UART byte at 0xA0400200 (= SYS_ADDR + 0x200),
// which is plain memory-mapped output, not part of the proof.
//
// The host (rust-input-gen) writes the block container starting with the
// `ZEG0` magic; to feed it to ziskemu it is framed as [u64 LE len][payload],
// so the input record is the container and `read_input()` returns a pointer to
// its first byte (the magic), 8-byte aligned.
#pragma once

#include <cstddef>
#include <cstdint>

#include "zkvm_io.h"

namespace zeg::zisk {

struct Input {
    const uint8_t *ptr;  // first byte of the payload (the ZEG0 container)
    uint64_t       len;  // payload length in bytes
};

// The input record.
inline Input read_input() {
    const uint8_t* ptr = nullptr;
    size_t len = 0;
    ::read_input(&ptr, &len);
    return Input{ptr, len};
}

// Emit a 32-byte value (e.g. the block hash) as the public output: the 32 bytes
// in order, which write_output packs little-endian into the first 8 u32 slots —
// what ziskemu's byte-wise output reader (get_output_8) and the native guest's hex
// dump read.
inline void set_output_bytes32(const uint8_t bytes[32]) { ::write_output(bytes, 32); }

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
