# Zisk for C/C++ Programs — A practical how-to

**Status**: community-contributed walkthrough (not official Zisk docs).
**Last verified**: 2026-05-19 against Zisk SDK 0.17.0 and rustc-zisk fork.
**Target**: developers porting an existing C or C++ codebase to the Zisk zkVM.

---

## TL;DR — Hello World in 30 seconds

```bash
# 1. hello.c
cat > hello.c <<'EOF'
int main(void) { return 42; }
EOF

# 2. _start.s (entry point — full explanation in Section 6)
cat > _start.s <<'EOF'
.section .text.init,"ax",@progbits
.global _start
.type _start, @function
_start:
    .option push
    .option norelax
    la gp, _global_pointer
    .option pop
    la sp, _init_stack_top
    call main
    csrr t0, marchid
    li   t1, 0xFFFEEEE
    beq  t0, t1, 1f
    li   t0, 0x100000     /* QEMU_EXIT_ADDR */
    li   t1, 0x5555       /* QEMU_EXIT_CODE */
    sw   t1, 0(t0)
    j    2f
1:  li   a7, 93           /* Zisk-hardware exit: ecall SYS_exit */
    ecall
2:  j    2b
EOF

# 3. zisk.ld (linker script from upstream Zisk Rust fork)
curl -fsSL https://raw.githubusercontent.com/0xPolygonHermez/rust/zisk/compiler/rustc_target/src/spec/targets/riscv64ima_zisk_zkvm_elf_linker_script.ld -o zisk.ld

# 4. Build
riscv-none-elf-gcc -march=rv64ima_zicsr -mabi=lp64 -mcmodel=medany \
    -nostartfiles -T zisk.ld \
    hello.c _start.s -o hello.elf

# 5. Run
ziskemu -e hello.elf -X
# Expected: STEPS > 0, TOTAL cost > 0, exit code 0
```

If this works, you're set. Read on for what each flag means and how to extend
from here.

---

## 1. Why this document exists

Zisk's official documentation (https://0xpolygonhermez.github.io/zisk-docs/)
and its SDK (`cargo-zisk`) target Rust-first. Most of the C/C++ infrastructure
exists implicitly inside the Rust toolchain fork
([`0xPolygonHermez/rust@zisk`](https://github.com/0xPolygonHermez/rust/tree/zisk)),
but isn't packaged for direct C/C++ consumption.

This guide collects what you need to know to compile and run a plain C or
C++ program on Zisk, learned by exploration. Each pitfall below was discovered
by running into the error message.

---

## 2. Prerequisites

### 2.1 Cross-compiler

You need a RISC-V 64-bit bare-metal GCC for the `riscv-none-elf` target.
The xPack distribution works well:

```bash
# https://xpack-dev-tools.github.io/riscv-none-elf-gcc-xpack/
# Install via xpm or manually unpack. Example path used in this doc:
RISCV_GCC=/path/to/xPacks/.../riscv-none-elf-gcc/15.2.0-1.1/.content/bin
export PATH="$RISCV_GCC:$PATH"
# Verify:
riscv-none-elf-gcc --version  # → 15.2.0 or newer
```

Any RISC-V toolchain that targets `riscv-none-elf` (or equivalent freestanding
ELF) should work. The Linux-targeted `riscv64-linux-gnu-gcc` will NOT — it
expects libc syscalls Zisk doesn't provide.

### 2.2 Zisk emulator (`ziskemu`)

Install via Zisk's own setup:

```bash
cargo install --git https://github.com/0xPolygonHermez/zisk cargo-zisk
cargo zisk setup
# `ziskemu` ends up in ~/.zisk/bin/ — add to PATH:
export PATH="$HOME/.zisk/bin:$PATH"
ziskemu --version
```

### 2.3 The linker script

Download from the upstream Zisk Rust fork (do NOT modify):

```bash
curl -fsSL https://raw.githubusercontent.com/0xPolygonHermez/rust/zisk/compiler/rustc_target/src/spec/targets/riscv64ima_zisk_zkvm_elf_linker_script.ld \
     -o zisk.ld
```

This is the same script the Zisk Rust toolchain uses. Keeping it pristine
means you benefit from upstream fixes without merging.

---

## 3. The minimal Hello World — what each piece does

### 3.1 `hello.c`

```c
int main(void) {
    return 42;
}
```

Nothing Zisk-specific. Note `main` returns `int`. The return value won't
automatically become an exit code (Zisk has no "process exit code" concept),
but the `_start` we'll write below picks it up if you want.

### 3.2 `_start.s` — the entry point

The Zisk emulator starts execution at the symbol `_start` (defined by
`ENTRY(_start)` in the linker script). Standard `crt0.o` from newlib defines
`_start`, but newlib's `_start` ends by calling `_exit` via a Linux syscall
that doesn't exist on Zisk. You need a custom `_start`.

Pattern copied verbatim from the official Zisk SDK
(`ziskos/entrypoint/src/lib.rs:294-329`):

```asm
.section .text.init,"ax",@progbits
.global _start
.type _start, @function
_start:
    /* Set up the global pointer (gp register).
       .option norelax prevents the linker from relaxing the 'la gp'
       into something that USES gp before it's set. */
    .option push
    .option norelax
    la gp, _global_pointer
    .option pop

    /* Set up the stack pointer to the top of the reserved stack region. */
    la sp, _init_stack_top

    /* Call main(). Return value lands in a0 (RISC-V calling convention). */
    call main

    /* Exit dispatch: are we on Zisk hardware or emulator?
       The 'marchid' CSR equals ARCH_ID_ZISK (0xFFFEEEE) on hardware. */
    csrr t0, marchid
    li   t1, 0xFFFEEEE
    beq  t0, t1, 1f

    /* QEMU/emulator exit: write magic to magic address. */
    li   t0, 0x100000   /* QEMU_EXIT_ADDR */
    li   t1, 0x5555     /* QEMU_EXIT_CODE */
    sw   t1, 0(t0)
    j    2f

1:  /* Zisk hardware exit: standard RISC-V ecall with a7=93 (SYS_exit). */
    li   a7, 93
    ecall

2:  /* In case the halt above doesn't actually halt, spin. */
    j    2b
```

Key points:
- `.text.init` is the section name expected by the linker script for the
  entry code (placed first in `.text`).
- `_global_pointer` and `_init_stack_top` are symbols defined by the linker
  script (not newlib-style names like `__global_pointer$`).
- The dual exit path (hardware vs emulator) means the same binary runs on
  both — `marchid` reports `0xFFFEEEE` only on Zisk hardware.

### 3.3 The build command

```bash
riscv-none-elf-gcc \
    -march=rv64ima_zicsr \
    -mabi=lp64 \
    -mcmodel=medany \
    -nostartfiles \
    -T zisk.ld \
    hello.c _start.s \
    -o hello.elf
```

Each flag is REQUIRED. Removing any will produce a non-functional binary.
Explanation in the next section.

### 3.4 Running

```bash
ziskemu -e hello.elf
echo $?           # expect: 0

ziskemu -e hello.elf -X | head -10
# Expected output:
#   STEPS                              8,516
#   TOTAL                        294,331,902 100.00%
#   ...
```

Non-zero STEPS confirms `main` executed (not a no-op halt).

---

## 4. Compiler flags explained

| Flag | What it does | What fails without it |
|---|---|---|
| `-march=rv64ima_zicsr` | Selects RISC-V 64-bit base + Multiply/Atomics + CSR extension | Without `_zicsr`: `unrecognized opcode csrr` and `ecall` errors in `_start.s` |
| `-mabi=lp64` | 64-bit pointers, 64-bit longs, no hard float | Without this: ABI mismatch with the Zisk runtime |
| `-mcmodel=medany` | "Medium any" code model: pointers can span ±2 GB | Without this: `relocation truncated to fit: R_RISCV_HI20` when accessing addresses far from `.text` (e.g., the data section at `0xa0020000` from code at `0x80000000`) |
| `-nostartfiles` | Don't link newlib's `crt0.o` | Without this: `undefined reference to __global_pointer$` (newlib's `_start` expects this symbol; the Zisk linker script provides `_global_pointer` without the dollar sign) |
| `-T zisk.ld` | Use the Zisk linker script | Without this: writable sections placed at default addresses (~0x10000), ziskemu refuses to load with "writable data section outside RAM bounds" |

Optional but recommended:

| Flag | Effect |
|---|---|
| `-ffreestanding` | Tells the compiler the C standard library is not fully available. Disables some compiler-built-in assumptions about `printf`, `malloc`, etc. |
| `-fno-exceptions -fno-rtti` (C++) | Smaller binary. The Zisk SDK doesn't provide exception unwinding tables. |
| `-Os` or `-O2` | Optimize for size or speed. `-O0` produces working but very large binaries. |
| `-Wl,--gc-sections` plus `-ffunction-sections -fdata-sections` | Dead-code elimination. Useful for keeping the ELF small. |

For C++:

```bash
riscv-none-elf-g++ \
    -march=rv64ima_zicsr \
    -mabi=lp64 \
    -mcmodel=medany \
    -nostartfiles \
    -ffreestanding \
    -fno-exceptions \
    -fno-rtti \
    -T zisk.ld \
    main.cpp _start.s -o main.elf
```

---

## 5. Memory layout reference

Zisk's address space (from the linker script + SDK):

```
Address         Size   Region              Purpose
─────────────────────────────────────────────────────────────────────────
0x0000_0000+    -      (reserved)          (don't write here)
0x0010_0000     4 B    QEMU_EXIT_ADDR      Write 0x5555 here to halt emulator
0x4000_0000     up to  INPUT_ADDR          Program input (max 128 MiB)
                128 MiB
0x8000_0000     256 MB ROM (code)          .text, .rodata
0xA000_0000     64 KB  general_registers   Reserved by runtime (NOLOAD)
0xA000_0200     -      UART_ADDR           Write bytes here for sys_println
0xA001_0000     64 KB  float_registers /   Reserved by runtime + SDK
                       OUTPUT_ADDR         public-outputs region
0xA002_0000     ~512   RAM (managed by ld) .output_data, .data, .bss,
                MiB                        stack (4 MiB), heap
0xBFFF_0000     64 KB  float_ram_data      Reserved at end of RAM
0xC000_0000     -      (end of RAM)
```

Symbols provided by the linker script (use via `extern char foo` in C):

| Symbol | Address | Meaning |
|---|---|---|
| `_global_pointer` | varies | gp register init value |
| `_bss_start` / `_bss_end` | varies | BSS section bounds |
| `_init_stack_top` | varies | Top of 4 MiB reserved stack |
| `_kernel_heap_bottom` | varies | Heap start (top of stack) |
| `_kernel_heap_top` | ≈0xBFFF0000 | Heap end |
| `_kernel_heap_size` | varies | Heap size |
| `_output_data_start` / `_end` | 0xA0020000 / +64K | Workspace for precompile ops (NOT the public output address — that's `OUTPUT_ADDR` at 0xA0010000) |

**Important**: `_output_data_start` (0xA0020000) and `OUTPUT_ADDR` (0xA0010000)
are different things. `_output_data_start` is a workspace used internally by
precompiles. `OUTPUT_ADDR` is where the SDK's `set_output_*` writes the proof's
public outputs.

---

## 6. The `_start` convention (deep dive)

The Zisk runtime expects:

1. **Entry point at `_start`**: declared via `ENTRY(_start)` in the linker
   script. Must be placed in the `.text.init` section to land at the start
   of `.text`.

2. **Stack pointer setup**: `sp` must point to a valid stack region
   (`_init_stack_top`). The stack grows downward from there, up to 4 MiB.

3. **Global pointer setup**: `gp` must hold `_global_pointer` for `gp-relative`
   addressing (used by GCC for small global variables). The `.option norelax`
   pragma is critical — without it, the linker might "relax" `la gp, ...`
   into a `gp`-relative instruction that uses `gp` before it's set, causing
   undefined behavior.

4. **Exit semantics**: when the program is done, it must halt. There are two
   mechanisms depending on the platform:
   - **On real Zisk hardware** (`marchid` CSR == `0xFFFEEEE`): use the
     standard RISC-V `ecall` with `a7 = 93` (SYS_exit per the RISC-V
     SYSTEM ABI).
   - **On QEMU or `ziskemu`**: write `0x5555` to address `0x100000` (a
     QEMU "magic exit" convention inherited from upstream RISC-V QEMU).

   The Zisk SDK's `_start` dispatches between these based on `marchid`.

If you don't halt explicitly, the emulator will keep stepping past the end
of `main` until it hits invalid memory or `--max-steps`. You'll see large
step counts and likely a crash.

---

## 7. Common errors and their fixes

### 7.1 "ELF contains writable data section at 0x... outside RAM bounds"

```
Error during emulation: Unknown("ELF contains writable data section
at 0x00013460-0x00013e00 outside RAM bounds (0xa0000000-0xc0000000).
Writable sections must be placed in RAM. Consider adjusting your
linker script.")
```

**Cause**: you forgot `-T zisk.ld`. GCC's default linker script puts `.data`
and `.bss` at low addresses (~`0x13460`). Zisk requires writable sections
inside `0xA0000000-0xC0000000`.

**Fix**: add `-T zisk.ld` to your link command.

### 7.2 "undefined reference to `__global_pointer$`"

```
crt0.o: in function `_start':
undefined reference to `__global_pointer$'
undefined reference to `__bss_start'
```

**Cause**: you forgot `-nostartfiles`. GCC is linking newlib's `crt0.o`, which
expects newlib-style symbol names (`__global_pointer$`, `__bss_start`) that
the Zisk linker script doesn't provide.

**Fix**: pass `-nostartfiles` and supply your own `_start.s` (Section 3.2).

### 7.3 "unrecognized opcode `csrr t0,marchid', extension `zicsr' required"

**Cause**: modern RISC-V toolchains split the CSR/system-call instructions
into a separate extension named `zicsr`. Plain `-march=rv64ima` doesn't
enable it.

**Fix**: use `-march=rv64ima_zicsr`.

### 7.4 "relocation truncated to fit: R_RISCV_HI20"

```
hello.c:(.text+0x10): relocation truncated to fit: R_RISCV_HI20
against symbol `_output_data_start' defined in .output_data section
```

**Cause**: GCC's default code model (`medlow`) assumes all addresses fit in
the lowest 2 GiB. The Zisk linker script puts `.text` at `0x80000000` and
`.data`/`.bss` at `0xA0020000+`, which is more than 2 GiB apart from `.text`
— `medlow` can't reach across.

**Fix**: use `-mcmodel=medany`. This emits `auipc + addi` pairs for absolute
addresses, which work across the full 32-bit signed range.

### 7.5 Program runs but produces 0 steps

If `ziskemu -e prog.elf -X` shows `STEPS: 0` or near-zero, your program
likely halted before reaching `main` (perhaps `_start` jumped directly to
the halt path, or `_global_pointer` was uninitialized, causing a crash).

**Fix**: double-check `_start.s` follows the pattern in Section 3.2.

### 7.6 Program hangs (infinite loop)

If `ziskemu` runs forever (or hits `--max-steps`), your `_start` likely
falls through past `main` without halting.

**Fix**: ensure the exit dispatch in `_start.s` is reached after `call main`.

---

## 8. Going beyond Hello World

### 8.1 Printing to UART

Zisk has a UART at `0xA0000200`. Writing a byte to this address prints it:

```c
static inline void uart_putc(char c) {
    *(volatile unsigned char *)0xA0000200 = (unsigned char)c;
}

void sys_println(const char *s) {
    while (*s) uart_putc(*s++);
    uart_putc('\n');
}

int main(void) {
    sys_println("hello from Zisk!");
    return 0;
}
```

Run with `ziskemu -e prog.elf` — ziskemu emits UART bytes to stdout by
default; no flag needed. (The `-c` flag inspects the `OUTPUT_ADDR`
public-outputs region after execution, which is a separate I/O
mechanism — see Section 8.3.)

### 8.2 Reading input

Zisk hands you an input buffer at `INPUT_ADDR = 0x40000000`. The layout is
NOT just "length + payload" — there's an 8-byte reserved header first:

```
INPUT_ADDR + 0..8   : reserved by ziskemu (zero-filled)
INPUT_ADDR + 8..16  : u64 LE length of first input chunk
INPUT_ADDR + 16..   : payload of first input chunk
(additional chunks follow with their own length prefix)
```

The Zisk Rust SDK encodes this convention as `INPUT_INITIAL_OFFSET = 8`
(see `ziskos/entrypoint/src/lib.rs`). C/C++ programs should match.

```c
#define ZISK_INPUT_ADDR        ((const volatile unsigned long *)0x40000000)
#define ZISK_INPUT_DATA_OFFSET 8  /* skip the reserved header */

typedef struct {
    const unsigned char *ptr;
    unsigned long        len;
} zisk_input_t;

static inline zisk_input_t read_input(void) {
    const volatile unsigned long *base =
        (const volatile unsigned long *)((const char *)ZISK_INPUT_ADDR + ZISK_INPUT_DATA_OFFSET);
    zisk_input_t inp;
    inp.len = base[0];                                /* length prefix */
    inp.ptr = (const unsigned char *)(base + 1);      /* payload start */
    return inp;
}
```

Provide input to ziskemu with `-i input.bin`. The file content is loaded
verbatim starting at `INPUT_ADDR + 8` (the reserved 8 bytes at offset 0 are
zero-filled by the emulator). So your file should be:

```
file byte 0..8   : u64 LE length of first chunk
file byte 8..    : first chunk payload (8-byte aligned)
```

Alternatively, use `--legacy-inputs <file>`: ziskemu wraps the file by
prepending its size as an 8-byte length prefix, so the file can be just the
raw payload.

Caveat: `ziskemu` panics if you read past the loaded input region (e.g.
`INPUT_ADDR + 24` when the file is 16 bytes). Always honor `inp.len`.

Note: the Zisk Rust SDK additionally calls a hint function
(`fcall_input_ready`) before reading from input memory. This is required
for proof generation (it tells the prover which input bytes the guest
needed) but not for ziskemu execution. C/C++ programs targeting only the
emulator can omit the fcall; programs that will be proved must add it.

### 8.3 Writing public outputs (proof-visible)

Use `OUTPUT_ADDR = 0xA0010000`. Each output is a u32 slot:

```c
static inline void set_output_u32(unsigned slot, unsigned int value) {
    volatile unsigned int *p = (volatile unsigned int *)0xA0010000;
    p[slot] = value;
}

static inline void set_output_u64(unsigned slot, unsigned long value) {
    set_output_u32(2 * slot,     (unsigned int)(value & 0xFFFFFFFF));
    set_output_u32(2 * slot + 1, (unsigned int)(value >> 32));
}
```

After execution, `ziskemu -e prog.elf -o output.bin` writes the output slots
to `output.bin`. The proof-system honors these values as the public
attestation of the computation.

### 8.4 Dynamic memory (malloc)

Newlib's malloc relies on `sbrk`, which needs a `_sbrk` implementation that
extends the heap. The simplest approach: a bump allocator.

```c
/* arena_malloc.c — minimal bump allocator */
extern char _kernel_heap_bottom;
extern char _kernel_heap_top;

static char *next = NULL;

void *malloc(unsigned long size) {
    if (!next) next = &_kernel_heap_bottom;
    /* align to 8 bytes */
    size = (size + 7) & ~7UL;
    char *p = next;
    next += size;
    if (next > &_kernel_heap_top) return NULL;  /* OOM */
    return p;
}

void free(void *p) { (void)p;  /* no-op: zkVM execution is single-shot */ }

void *calloc(unsigned long n, unsigned long size) {
    unsigned long total = n * size;
    char *p = (char *)malloc(total);
    if (p) for (unsigned long i = 0; i < total; ++i) p[i] = 0;
    return p;
}

void *realloc(void *p, unsigned long size) {
    char *q = (char *)malloc(size);
    /* assume the old allocation fits; copy is a no-op for simplicity */
    if (p && q) {
        char *src = (char *)p;
        for (unsigned long i = 0; i < size; ++i) q[i] = src[i];
    }
    return q;
}
```

Why `free` as no-op: a zkVM execution runs the program once start to finish.
No need to reclaim memory.

### 8.5 C++ standard library (`std::string`, `std::vector`, ...)

Switching from `gcc` to `g++` is necessary but not sufficient for C++.
There are at least four problems you'll discover by trying:

**Problem 1: `g++` treats `.c` files as C++ by default.** This mangles
symbols you intended as C. Either rename your stub files to `.cpp` and
wrap them in `extern "C"`, or compile them separately with `gcc`.

**Problem 2: libc symbols pulled in by libstdc++.** Even the simplest
C++ program (just `#include <string>`) drags in `getentropy_r` via
`std::random_device` instantiation in libstdc++'s headers. The linker
fails with `undefined reference to _getentropy`. Provide a stub (it
should NEVER be called at runtime — non-determinism would break proof
soundness, so halt on entry):

```cpp
// runtime_stubs.cpp
extern "C" int _getentropy(void *buf, size_t len) {
    (void)buf; (void)len;
    /* Non-determinism forbidden — halt loudly. */
    const char msg[] = "FATAL: _getentropy called\n";
    volatile unsigned char *uart = (volatile unsigned char *)0xA0000200;
    for (const char *p = msg; *p; ++p) *uart = (unsigned char)*p;
    *(volatile unsigned int *)0x100000 = 0x5555;
    for (;;) {}
}
```

**Problem 3: missing allocator.** `new` calls `operator new` which calls
`malloc`. Newlib's `malloc` calls `_sbrk` which isn't implemented on
Zisk. Without a working allocator, `new` writes to wild memory and
ziskemu panics with something like `write_silent invalid addr=8`.
Provide a custom allocator (see Section 8.4) and wire `operator new` /
`operator delete` to it:

```cpp
// operator_new.cpp
#include <cstddef>
extern "C" void *malloc(std::size_t);
extern "C" void  free(void *);

void *operator new(std::size_t n)              { return malloc(n); }
void *operator new[](std::size_t n)            { return malloc(n); }
void  operator delete(void *p) noexcept        { free(p); }
void  operator delete[](void *p) noexcept      { free(p); }
void  operator delete(void *p, std::size_t) noexcept   { free(p); }
void  operator delete[](void *p, std::size_t) noexcept { free(p); }

// C++ ABI stubs (no-ops in a single-threaded freestanding env).
extern "C" {
    void __cxa_pure_virtual(void) {
        /* should never be called; halt if it is */
        *(volatile unsigned int *)0x100000 = 0x5555;
    }
    int __cxa_atexit(void (*)(void *), void *, void *) { return 0; }
    void __cxa_finalize(void *) {}
}
```

**Problem 4: ELF section alignment.** Even with `-fno-exceptions`,
libstdc++ pulls in `.gcc_except_table.*` metadata sections (one per
throw helper). These have 1-byte or 4-byte alignment, while ziskemu
requires **all loaded sections to start at 8-byte-aligned addresses**.
Symptom: `Mem::add_read_section() got a start address=0x... not
aligned to 8 bytes`.

Workarounds, in order of preference:

  - **Discard the metadata** via a linker script overlay:
    ```ld
    /DISCARD/ : {
        *(.gcc_except_table*)
        *(.eh_frame*)
    }
    ```
    This is the cleanest fix — we don't use exceptions, so the metadata
    is dead weight.

  - **Force alignment** by adding `*(.gcc_except_table*) . = ALIGN(8);`
    blocks to the `.rodata` section of the linker script.

  - **Strip after linking** with `riscv-none-elf-objcopy
    --remove-section=.gcc_except_table*` — works but adds a build step.

**Problem 5: `__throw_*` undeclared with `-ffreestanding`.** The
`-ffreestanding` flag suppresses the include path that brings in
`<bits/functexcept.h>`, so calls inside libstdc++ headers to
`__throw_length_error` etc. fail to compile (e.g. "is not a member of
std"). Drop `-ffreestanding` when compiling C++.

Once you've solved problems 1-5, `std::string`, `std::vector`,
`std::map`, etc. work as expected. If you need exceptions, you'll
additionally have to provide unwind tables and the exception runtime,
which is significantly more work and usually unnecessary in a zkVM
context (you can `static_assert` or `abort()` on error instead).

### 8.6 Forbidden operations

Zisk requires **deterministic execution** for proof soundness. The following
must be banned (the SDK Rust runtime aborts on them; you should too in C/C++):

- `rand()`, `random()`, `getentropy()`, reading `/dev/urandom`.
- Time-based decisions (`clock()`, `gettimeofday()`).
- Threading (zkVM is single-threaded by construction).
- System calls other than the Zisk-defined exit and precompile syscalls.

Provide trapping stubs:

```c
int rand(void)                          { halt(); }
int getentropy(void *, unsigned long)   { halt(); return 0; }
time_t time(time_t *p)                  { halt(); return 0; }
/* etc. */

static void halt(void) __attribute__((noreturn));
static void halt(void) {
    *(volatile unsigned int *)0x100000 = 0x5555;
    for (;;) {}
}
```

### 8.7 Calling precompiles (keccak, secp256k1, BN254, BLS12-381)

Zisk exposes cryptographic primitives as CSR-based syscalls. Each precompile
has a CSR ID:

| Precompile | CSR | Operation |
|---|---|---|
| `syscall_keccakf` | 0x800 | Keccak-f[1600] permutation |
| `syscall_arith256` | 0x801 | 256-bit multiply-add |
| `syscall_arith256_mod` | 0x802 | 256-bit mul + reduce mod p |
| `syscall_sha256` | 0x803 | SHA-256 compression |
| `syscall_secp256k1_add` | 0x804 | secp256k1 EC point add |
| `syscall_secp256k1_dbl` | 0x805 | secp256k1 EC point double |
| `syscall_bn254_curve_add` | 0x806 | BN254 G1 point add |
| `syscall_bn254_curve_dbl` | 0x807 | BN254 G1 point double |
| `syscall_bn254_fp2_addmod` | 0x808 | BN254 Fp2 add |
| `syscall_bn254_fp2_submod` | 0x809 | BN254 Fp2 sub |
| `syscall_bn254_fp2_mulmod` | 0x80A | BN254 Fp2 mul |
| `syscall_arith384_mod` | 0x80B | 384-bit mul + reduce mod p (BLS Fp) |
| `syscall_bls12_381_curve_add` | 0x80C | BLS12-381 G1 add |
| `syscall_bls12_381_curve_dbl` | 0x80D | BLS12-381 G1 double |
| `syscall_bls12_381_fp2_addmod` | 0x80E | BLS12-381 Fp2 add |
| `syscall_bls12_381_fp2_submod` | 0x80F | BLS12-381 Fp2 sub |
| `syscall_bls12_381_fp2_mulmod` | 0x810 | BLS12-381 Fp2 mul |
| `syscall_add256` | 0x811 | 256-bit add with carry |
| `syscall_dma_memcpy` | 0x813 | Fast DMA-style memcpy |
| `syscall_dma_memcmp` | 0x814 | DMA memcmp |
| `syscall_dma_inputcpy` | 0x815 | Memcpy from INPUT_ADDR region |
| `syscall_dma_xmemset` | 0x816 | DMA memset |

Call them via inline assembly:

```cpp
inline void syscall_keccakf(unsigned long *state /* &state[25] */) {
    register unsigned long a0 asm("a0") = reinterpret_cast<unsigned long>(state);
    asm volatile("csrs 0x800, %0" : : "r"(a0) : "memory");
}
```

The argument is passed in register `a0`; the CSR ID is the precompile
selector. For precompiles that return a value (e.g., `syscall_add256` returns
the carry-out), use `csrrs` to read back:

```cpp
inline unsigned long syscall_add256(struct AddParams *p) {
    register unsigned long a0 asm("a0") = reinterpret_cast<unsigned long>(p);
    unsigned long carry_out;
    /* `=&r` (early-clobber) forces a register different from rs1, otherwise
       Zisk's riscv2zisk doesn't route through the add256 precompile. */
    asm volatile("csrrs %0, 0x811, %1" : "=&r"(carry_out) : "r"(a0) : "memory");
    return carry_out;
}
```

Each precompile expects parameters via a struct of pointers (mostly aligned
to 8 bytes). The exact layout is documented in the Zisk SDK headers
(`ziskos/entrypoint/src/syscalls/*.rs`).

---

## 9. Reference: ABI summary

| Item | Value |
|---|---|
| Target triple | `riscv64ima-zisk-zkvm-elf` |
| Pointer width | 64 bits |
| Long width | 64 bits |
| Endianness | Little-endian |
| Code model | medany |
| Calling convention | RISC-V lp64 (integers in a0-a7, return in a0/a1) |
| Stack alignment | 16 bytes |
| Required march | `rv64ima_zicsr` |
| Required mabi | `lp64` |
| Entry symbol | `_start` |
| Halt convention | `csrr marchid` → if `0xFFFEEEE`, `ecall a7=93`; else `sw 0x5555, 0(0x100000)` |
| Arch ID | `0xFFFEEEE` |
| QEMU exit address | `0x100000` |
| QEMU exit code | `0x5555` |

---

## 10. Reference: addresses

| Symbol / address | Value | Purpose |
|---|---|---|
| `INPUT_ADDR` | `0x40000000` | Program input region (first 8 bytes = length, then payload) |
| `ROM` | `0x80000000` | `.text` + `.rodata` |
| `general_registers` | `0xA0000000` | Reserved by runtime |
| `UART_ADDR` | `0xA0000200` | Write bytes here for console output |
| `OUTPUT_ADDR` | `0xA0010000` | Public outputs (32-bit slot array) |
| `_output_data_start` | `0xA0020000` | Linker-managed workspace for precompiles |
| `.data` / `.bss` | `0xA0030000+` | Program data |
| Stack top | varies | `_init_stack_top`, 4 MiB above .bss |
| Heap | varies | `_kernel_heap_bottom` to `_kernel_heap_top` |
| `float_ram_data` | `0xBFFF0000` | Reserved (64 KB at top of RAM) |

---

## 11. Suggested upstream improvements

Several rough edges in the current setup could be smoothed out with small
upstream changes. These are observations, not criticism — the Zisk team
has done excellent work bringing Rust to zkVM; the C/C++ path just hasn't
received the same attention.

### 11.1 Add newlib-style symbol aliases to the linker script

```ld
PROVIDE(__global_pointer$ = _global_pointer);
PROVIDE(__bss_start       = _bss_start);
PROVIDE(__bss_end__       = _bss_end);
PROVIDE(__stack_top       = _init_stack_top);
PROVIDE(__heap_start      = _kernel_heap_bottom);
PROVIDE(__heap_end        = _kernel_heap_top);
```

Pure addition (`PROVIDE` only defines if absent). Zero risk to the Rust
path. Allows newlib's stock `crt0.o` to link cleanly, eliminating the need
for users to write their own `_start.s`.

### 11.2 Export magic constants as linker script symbols

```ld
PROVIDE(ZISK_ARCH_ID            = 0xFFFEEEE);
PROVIDE(ZISK_QEMU_EXIT_ADDR     = 0x100000);
PROVIDE(ZISK_QEMU_EXIT_CODE     = 0x5555);
PROVIDE(ZISK_INPUT_ADDR         = 0x40000000);
PROVIDE(ZISK_OUTPUT_ADDR        = 0xA0010000);
PROVIDE(ZISK_UART_ADDR          = 0xA0000200);
```

Allows assembly and C code to reference these by name (`la t0, ZISK_QEMU_EXIT_ADDR`)
instead of hardcoding hex literals. Stable ABI surface for the future.

### 11.3 Ship a `zisk_crt0.o` for C/C++ users

A precompiled object file with the standard `_start` would let C/C++ users do:

```bash
riscv-none-elf-gcc -lzisk-crt0 ...
```

instead of manually writing `_start.s`. The Zisk Rust toolchain effectively
has this baked in; exposing it for non-Rust users would save ~30 LoC of
boilerplate per project.

### 11.4 Ship a `libzisk-runtime.a` with libc stubs

Combined with 11.3, this would package:

- `_start` (entry point)
- `malloc`/`free`/`calloc`/`realloc` (arena allocator)
- C++ operator `new`/`delete`
- `__cxa_*` C++ ABI stubs
- Trapping stubs for `getentropy`, `rand`, `time`, etc.
- `printf` → UART helpers

Currently each project (`zilkworm`, `zec-reth`, etc.) reimplements these.
Upstreaming would eliminate hundreds of duplicated lines per project.

### 11.5 Document the C/C++ build path in the official Zisk book

A page covering items 1-7 of this guide. Even just the section "Common
errors and their fixes" (Section 7) would save new users hours of trial and
error.

---

## 12. References

- Zisk repository: https://github.com/0xPolygonHermez/zisk
- Zisk Rust toolchain fork: https://github.com/0xPolygonHermez/rust/tree/zisk
- Linker script source: https://github.com/0xPolygonHermez/rust/blob/zisk/compiler/rustc_target/src/spec/targets/riscv64ima_zisk_zkvm_elf_linker_script.ld
- Zisk official docs: https://0xpolygonhermez.github.io/zisk-docs/
- Zisk SDK entrypoint (`_start` reference): `ziskos/entrypoint/src/lib.rs` in the Zisk repo
- xPack riscv-none-elf-gcc: https://xpack-dev-tools.github.io/riscv-none-elf-gcc-xpack/
- RISC-V SYSTEM ABI: https://github.com/riscv-non-isa/riscv-elf-psabi-doc

---

*Found a mistake or missing detail? File an issue or PR against this document.*
