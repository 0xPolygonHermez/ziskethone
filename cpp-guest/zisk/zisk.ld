/* Copy of zisk's own ziskbuild/zisk_linker_script.ld, taken from the
 * pre-develop-1.2.0-alpha pin (commit 4b11d589c). Sourced directly from
 * upstream instead of hand-maintained, so it can be re-diffed against the
 * pinned zisk repo on any future toolchain bump.
 *
 * ONE deviation from upstream: the `text` segment is FLAGS(1) (execute-only),
 * not FLAGS(5) (execute-and-read) — see the PHDRS block below. */

OUTPUT_FORMAT("elf64-littleriscv")
OUTPUT_ARCH("riscv")
ENTRY(_start)

MEMORY {
  rom   (xa) : ORIGIN = 0x80000000, LENGTH = 0x08000000
  ram   (wxa) : ORIGIN = 0xa0000000, LENGTH = 0x20000000
}

PHDRS {
  /* FLAGS(1) = PF_X only: execute, NOT read. ZisK's ELF loader treats a
     PF_X | PF_R segment as "could be code or data anywhere", so it materializes
     the WHOLE segment a second time as read-only ROM data (elf_extraction.rs,
     `if is_read { out.ro.push(...) }`) and prints a WARNING banner saying
     execute-and-read is slower. Our .text is code only — every constant lands in
     .rodata/.srodata below, and memset.s's jump table is jumped into, not loaded
     — so dropping PF_R costs nothing and keeps 1.2 MB of instructions out of the
     readable ROM image. Upstream ships FLAGS(5); this is the only difference.
     Guard: if something ever does read from .text, its bytes are no longer in ROM
     data, reads return 0, and the block hash changes — the end-to-end check
     catches it. */
  text PT_LOAD FLAGS(1);
  rodata PT_LOAD FLAGS(4);
  data PT_LOAD FLAGS(6);
  bss PT_LOAD FLAGS(6);
  output_data PT_LOAD FLAGS(6);
  general_registers_data PT_LOAD FLAGS(6);
  float_registers_data PT_LOAD FLAGS(6);
  stack_data PT_LOAD FLAGS(6);
}

_stack_size                  = 0x400000;  /* 4 MB reserved */
_general_registers_data_size = 0x8000;    /* 32 kB */
_float_registers_data_size   = 0x8000;    /* 32 kB */
_output_data_size            = 0x20000;   /* 128 KB reserved */
_float_ram_data_size         = 0x10000;   /* 64 KB reserved */

/*

0x4000_0000  ┌────────────────────┐← free input entry
             │    input data      │
             │       (1GB)        │
0x7FFF_FFFF  └────────────────────┘
0x8000_0000  ┌────────────────────┐
             │     ROM data       │
             │      (128MB)       │
0x87FF_FFFF  └────────────────────┘
                       ↑
                    384 MB
                       ↓
0xA000_0000  ┌────────────────────┐← _init_stack_bottom
             │                    │
             │   stack ↑ 4MB      │
             │                    │
0xA040_0000  ├────────────────────┤← _init_stack_top
             │ .general_registers │  32 KB reserved (NOLOAD)
             │  0x8000 bytes      │  _general_registers_data_start / _end
0xA040_8000  ├────────────────────┤
             │ .float_registers   │  32 KB reserved (NOLOAD)
             │  0x8000 bytes      │  _float_registers_data_start / _end
0xA041_0000  ├────────────────────┤
             │ .output_data       │  128 KB reserved (NOLOAD)
             │  0x20000 bytes     │  _output_data_start / _end
0xA043_0000  ├────────────────────┤
             │   .data            │
             │   .bss             │
             ├────────────────────┤ ← _bss_end, _heap_bottom
             │   heap ↓           │
             │                    │
             │                    │
             │                    │
             │                    │
0xBFFF_0000  ├────────────────────┤ ← _heap_top
             │ float ram          │
0xC000_0000  └────────────────────┘

*/

SECTIONS
{
  .text : { *(.text.init) *(.text .text.*)} >rom AT>rom :text

  . = ALIGN(8);
  PROVIDE(_global_pointer = .);
  .rodata : { *(.rodata .rodata.*)} >rom AT>rom :rodata

  /* C++ static constructors / destructors (run by _start before/after main),
     placed in ROM: the entries are link-time-constant function pointers, never
     written. KEEP prevents --gc-sections from dropping them. The init/fini array
     bound symbols are referenced (strongly) by the runtime, so this section MUST
     be present when linking against libziskos. Empty when the program has no
     static initializers (start == end), so it costs nothing. */
  . = ALIGN(8);
  .init_array : {
    PROVIDE(__init_array_start = .);
    KEEP(*(SORT_BY_INIT_PRIORITY(.init_array.*)))
    KEEP(*(.init_array))
    PROVIDE(__init_array_end = .);
  } >rom AT>rom :rodata

  .fini_array : {
    PROVIDE(__fini_array_start = .);
    KEEP(*(SORT_BY_INIT_PRIORITY(.fini_array.*)))
    KEEP(*(.fini_array))
    PROVIDE(__fini_array_end = .);
  } >rom AT>rom :rodata

  /* reserve stack at the beginning of RAM */
  . = ORIGIN(ram);

  /* reserved space for stack data */
  .stack_data (NOLOAD): {
  PROVIDE(_stack_start = .);
  PROVIDE(_init_stack_bottom = .); # alias for the start of the reserved stack region
  . = . + _stack_size;
  PROVIDE(_init_stack_top = .); # reserve 4M bytes for the initialisation stack
  } >ram AT>ram :stack_data

  /* reserved space for general registers */

  .general_registers_data (NOLOAD) : {
    PROVIDE(_general_registers_data_start = .);
    . = . + _general_registers_data_size;
    PROVIDE(_general_registers_data_end = .);
  } >ram AT>ram :general_registers_data

  /* reserved space for float registers */

  .float_registers_data (NOLOAD) : {
    PROVIDE(_float_registers_data_start = .);
    . = . + _float_registers_data_size;
    PROVIDE(_float_registers_data_end = .);
  } >ram AT>ram :float_registers_data

  /* reserved space for output data */

  .output_data (NOLOAD) : {
    PROVIDE(_output_data_start = .);
    . = . + _output_data_size;
    PROVIDE(_output_data_end = .);
  } >ram AT>ram :output_data

  .data : { *(.data .data.* .sdata .sdata.*) } >ram AT>ram :data

  .bss : {
    PROVIDE(_bss_start = .);
    *(.bss .bss.* .sbss .sbss.*);
    PROVIDE(_bss_end = .); # ... and one at the end
  } >ram AT>ram :bss

  PROVIDE(_heap_bottom = .);
  PROVIDE(_heap_top = ORIGIN(ram) + LENGTH(ram) - _float_ram_data_size);
  PROVIDE(_heap_size = _heap_top - _heap_bottom);

  _end = .;
}
