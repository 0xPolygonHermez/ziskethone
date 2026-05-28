OUTPUT_FORMAT("elf64-littleriscv")
OUTPUT_ARCH("riscv")
ENTRY(_start)

MEMORY {
  rom   (xa) : ORIGIN = 0x80000000, LENGTH = 0x10000000
  ram   (wxa) : ORIGIN = 0xa0020000, LENGTH = 0x1FFE0000
}

PHDRS {
  text PT_LOAD FLAGS(5);
  rodata PT_LOAD FLAGS(4);
  data PT_LOAD FLAGS(6);
  bss PT_LOAD FLAGS(6);
  output_data PT_LOAD FLAGS(6);
}

_stack_size           = 0x400000;  /* 4 MB reserved */
_output_data_size     = 0x10000;   /* 64 KB reserved */
_float_ram_data_size  = 0x10000;   /* 64 KB reserved */

/*

0xA0000000  ┌────────────────────┐
            │ .general_registers │  64 KB reserved (NOLOAD)
            │  0x10000 bytes     │  _general_registers_start / _end
0xA0010000  ├────────────────────┤
            │ .float_registers   │  64 KB reserved (NOLOAD)
            │  0x10000 bytes     │  _float_registers_start / _end
0xA001FFFF  └────────────────────┘ ← _kernel_heap_top
0xA0020000  ┌────────────────────┐
            │ .output_data       │  64 KB reserved (NOLOAD)
            │  0x10000 bytes     │  _output_data_start / _end
0xA0030000  ├────────────────────┤
            │   .data            │
            │   .bss             │
            ├────────────────────┤ ← _bss_end
            │   stack ↑ 4MB      │
            ├────────────────────┤ ← _init_stack_top = _kernel_heap_bottom
            │   heap ↑           │  (bump allocator grows upward)
            │                    │
0xBFFEFFFF  │                    │
0xBFFF0000  ├────────────────────┤ ← _kernel_heap_top
            │ float ram          │
0xC0000000  └────────────────────┘

*/

SECTIONS
{
  .text : { *(.text.init) *(.text .text.*)} >rom AT>rom :text

  . = ALIGN(8);
  PROVIDE(_global_pointer = .);
  /* SUBALIGN(8) forces every input section placed here to start at an
     8-byte boundary, regardless of its own alignment. Required because
     libstdc++ emits many small .srodata.<mangled> sections with align=1,
     which Zisk's runtime rejects (Mem::add_read_section requires 8-byte
     aligned start addresses). Also extended the wildcard to collect the
     short-rodata family. */
  .rodata : SUBALIGN(8) {
    *(.rodata .rodata.*)
    *(.srodata .srodata.* .srodata.cst*)
  } >rom AT>rom :rodata


  /* reserved space for output data */

  .output_data (NOLOAD) : {
    PROVIDE(_output_data_start = .);
    . = . + _output_data_size; 
    PROVIDE(_output_data_end = .);
  } >ram AT>ram :output_data

  .data : {
    /* PROGBITS data first so the output section stays type PROGBITS;
       if init_array were first, the whole .data inherits type INIT_ARRAY
       and ziskemu silently drops its contents (calls would jump to 0). */
    *(.data .data.* .sdata .sdata.*)

    . = ALIGN(8);
    PROVIDE_HIDDEN(__init_array_start = .);
    KEEP(*(SORT_BY_INIT_PRIORITY(.init_array.*) SORT_BY_INIT_PRIORITY(.ctors.*)))
    KEEP(*(.init_array EXCLUDE_FILE(*crtbegin.o *crtbegin?.o *crtend.o *crtend?.o) .ctors))
    PROVIDE_HIDDEN(__init_array_end = .);
    . = ALIGN(8);
    PROVIDE_HIDDEN(__preinit_array_start = .);
    KEEP(*(.preinit_array))
    PROVIDE_HIDDEN(__preinit_array_end = .);
  } >ram AT>ram :data

  .bss : {
    PROVIDE(_bss_start = .);
    *(.bss .bss.*);
    PROVIDE(_bss_end = .); # ... and one at the end
  } >ram AT>ram :bss

  /* RISC-V lp64 ABI requires sp to be 16-byte aligned at every
     function-call boundary. ALIGN(16) here makes _init_stack_top
     16-aligned so the initial sp set by _start.s is ABI-compliant;
     ALIGN(8) (the previous value) gave us 8-byte alignment, which
     happened to not crash anything visible but violates the ABI and
     breaks intrinsics / vector code that depend on 16-byte sp. */
  . = ALIGN(16);
  PROVIDE(_init_stack_top = . + _stack_size); # reserve 4M bytes for the initialisation stack

  PROVIDE(_kernel_heap_bottom = _init_stack_top);
  PROVIDE(_kernel_heap_top = ORIGIN(ram) + LENGTH(ram) - _float_ram_data_size);
  PROVIDE(_kernel_heap_size = _kernel_heap_top - _kernel_heap_bottom);

  _end = .;

  /DISCARD/ : {
    /* Discard exception-handling metadata. libstdc++ links these even with
       -fno-exceptions, and they break Zisk's 8-byte alignment requirement
       on read sections. Safe to drop because Zisk programs never unwind. */
    *(.gcc_except_table .gcc_except_table.*)
    *(.eh_frame .eh_frame.*)
    *(.eh_frame_hdr .eh_frame_hdr.*)
  }
}