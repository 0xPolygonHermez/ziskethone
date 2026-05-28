/* zisk_io.h — I/O primitives for Zisk guest programs.
 *
 * Header-only: no .c counterpart needed.
 *
 * Provides:
 *   - UART output (uart_putc, sys_println, sys_print_u64_hex)
 *   - Input reading (read_input → ptr + len)
 *   - Public output writing (set_output_u32, set_output_u64)
 */
#ifndef ZISK_GUEST_ZISK_IO_H_
#define ZISK_GUEST_ZISK_IO_H_

/* ---------- UART output ---------- */
#define ZISK_UART_ADDR ((volatile unsigned char *)0xA0000200)

static inline void uart_putc(char c) {
    *ZISK_UART_ADDR = (unsigned char)c;
}

static inline void sys_println(const char *s) {
    while (*s) uart_putc(*s++);
    uart_putc('\n');
}

static inline void sys_print_u64_hex(unsigned long v) {
    static const char hex[] = "0123456789abcdef";
    for (int i = 60; i >= 0; i -= 4) {
        uart_putc(hex[(v >> i) & 0xF]);
    }
}

/* ---------- Input region ---------- */
/* Layout (observed empirically with ziskemu):
 *   INPUT_ADDR + 0..8  : reserved by ziskemu (zero-filled)
 *   INPUT_ADDR + 8..16 : u64 LE length of first input chunk
 *   INPUT_ADDR + 16..  : first chunk payload (length bytes)
 *   (additional chunks follow with their own length prefix)
 *
 * The Zisk Rust SDK starts reading at INPUT_ADDR + 8 (its
 * INPUT_INITIAL_OFFSET) — matching the layout above.
 */
#define ZISK_INPUT_ADDR        ((const volatile unsigned long *)0x40000000)
#define ZISK_INPUT_DATA_OFFSET 8  /* skip the 8-byte reserved header */

typedef struct {
    const unsigned char *ptr;
    unsigned long        len;
} zisk_input_t;

static inline zisk_input_t read_input(void) {
    const volatile unsigned long *base =
        (const volatile unsigned long *)((const char *)ZISK_INPUT_ADDR + ZISK_INPUT_DATA_OFFSET);
    zisk_input_t inp;
    inp.len = base[0];                                    /* length prefix */
    inp.ptr = (const unsigned char *)(base + 1);          /* payload start */
    return inp;
}

/* ---------- Public outputs ---------- */
/* OUTPUT_ADDR is a u32 slot array (Zisk public-outputs convention). */
#define ZISK_OUTPUT_ADDR ((volatile unsigned int *)0xA0010000)

static inline void set_output_u32(unsigned slot, unsigned int value) {
    ZISK_OUTPUT_ADDR[slot] = value;
}

static inline void set_output_u64(unsigned slot, unsigned long value) {
    set_output_u32(2 * slot,     (unsigned int)(value & 0xFFFFFFFFu));
    set_output_u32(2 * slot + 1, (unsigned int)(value >> 32));
}

#endif  /* ZISK_GUEST_ZISK_IO_H_ */
