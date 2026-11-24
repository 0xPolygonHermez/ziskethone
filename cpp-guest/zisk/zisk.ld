/* Copy of zisk's own ziskbuild/zisk_linker_script.ld, taken from the ZisK
 * feat/addr-33-bits branch (33-bit addresses, 2 GB RAM). Sourced directly from
 * upstream so it can be re-diffed against the pinned zisk repo on any future
 * toolchain bump.
 *
 * Memory map (33-bit addresses): input data at 0x2000_0000 (2 GB), ROM at
 * 0xA800_0000 (128 MB), a 256 MB unmapped stack guard below RAM, and 2 GB of RAM
 * at 0xC000_0000, which ends at 0x1_4000_0000, above the 32-bit range. The float
 * and ZisK-library scratch regions are reserved at the bottom of RAM, right after
 * the output region, so the heap runs to the end of the RAM the guest is linked
 * for: 512 MB with this script (what a ZisK prover reserves by default), 2 GB with
 * zisk_ram2gb.ld (a prover built with its `ram_2gb` feature), which sets
 * ZISK_RAM_SIZE and includes this script.
 *
 * The code is linked with -mcmodel=medany, which reaches +-2 GiB from the ROM,
 * i.e. up to 0x1_2800_0000 (_pc_reach_end). .data and .bss must end below it (the
 * ASSERT at the end of SECTIONS); the top of the heap is beyond it, so the guest
 * must never take the address of _heap_top / _heap_end with a PC-relative
 * instruction: runtime.cpp reads it from a 64-bit word in .rodata instead (see
 * zeg_heap_top in _start.s).
 *
 * One local deviation from upstream remains: each output section also gathers
 * its .gnu.linkonce.* counterpart (and .rodata keeps .rodata.zeg_build_flags). A
 * GCC configured without COMDAT support (e.g. a patched -mzisk-dma compiler built
 * without seeing the assembler, see patches/gcc/) emits those in place of COMDAT
 * .text.* and .bss.* groups, and an uncollected linkonce .bss became an orphan
 * placed at _heap_bottom, overlapping the heap (modexp's exp_bits_buf). */

OUTPUT_FORMAT("elf64-littleriscv")
OUTPUT_ARCH("riscv")
ENTRY(_start)

MEMORY {
  rom   (xa) : ORIGIN = 0xA8000000, LENGTH = 0x08000000
  ram   (wxa) : ORIGIN = 0xC0000000, LENGTH = 0x80000000
}

PHDRS {
  text PT_LOAD FLAGS(1);
  rodata PT_LOAD FLAGS(4);
  data PT_LOAD FLAGS(6);
  bss PT_LOAD FLAGS(6);
  output_data PT_LOAD FLAGS(6);
  float_ram_data PT_LOAD FLAGS(6);
  zisklib_ram_data PT_LOAD FLAGS(6);
  general_registers_data PT_LOAD FLAGS(6);
  float_registers_data PT_LOAD FLAGS(6);
  stack_data PT_LOAD FLAGS(6);
}

_stack_size                  = 0x400000;  /* 4 MB reserved */
_general_registers_data_size = 0x8000;    /* 32 kB */
_float_registers_data_size   = 0x8000;    /* 32 kB */
_output_data_size            = 0x20000;   /* 128 KB reserved */
_float_ram_data_size         = 0x10000;   /* 64 KB reserved (float library RAM);
                                             keep in sync with FLOAT_LIB_RAM_SIZE in core/src/mem.rs */
_zisklib_ram_data_size       = 0x30000;   /* 192 KB reserved (ZisK library scratch);
                                             keep in sync with ZISKLIB_RAM_SIZE in core/src/mem.rs */
/* The guest is linked with the medium code model: PC-relative addressing reaches +-2GiB from
   the code, which starts at ORIGIN(rom). Everything the code addresses directly (.data, .bss,
   the system regions) must stay below this limit; the heap beyond it is reached through
   pointers. Keep in sync with PC_REACH_END in core/src/mem.rs. */
_pc_reach_end                = ORIGIN(rom) + 0x80000000;

/* RAM the guest uses, from ORIGIN(ram); the heap ends there, and the tx arena
   (runtime.cpp) starts there and grows down, so the guest writes at the top of
   this RAM from its first transaction. A ZisK prover reserves 512 MB of the 2 GB
   window by default, the whole window with its `ram_2gb` feature, and any access
   beyond it faults: link for the RAM of the prover that runs the ELF. */
_zisk_ram_size               = DEFINED(ZISK_RAM_SIZE) ? ZISK_RAM_SIZE : 0x20000000;
ASSERT(_zisk_ram_size == 0x20000000 || _zisk_ram_size == 0x80000000,
       "ZISK_RAM_SIZE must be 512 MB (0x20000000) or 2 GB (0x80000000)")

/*

0x2000_0000    ┌────────────────────┐← free input entry
               │    input data      │
               │       (2GB)        │
0x9FFF_FFFF    └────────────────────┘
0xA800_0000    ┌────────────────────┐
               │     ROM data       │
               │      (128MB)       │
0xAFFF_FFFF    └────────────────────┘
                         ↑
                     256 MB (stack guard, unmapped)
                         ↓
0xC000_0000    ┌────────────────────┐← _init_stack_bottom
               │                    │
               │   stack ↑ 4MB      │
               │                    │
0xC040_0000    ├────────────────────┤← _init_stack_top
               │ .general_registers │  32 KB reserved (NOLOAD)
               │  0x8000 bytes      │  _general_registers_data_start / _end
0xC040_8000    ├────────────────────┤
               │ .float_registers   │  32 KB reserved (NOLOAD)
               │  0x8000 bytes      │  _float_registers_data_start / _end
0xC041_0000    ├────────────────────┤
               │ .output_data       │  128 KB reserved (NOLOAD)
               │  0x20000 bytes     │  _output_data_start / _end
0xC043_0000    ├────────────────────┤
               │ float ram          │  64 KB reserved = FLOAT_LIB_RAM (core/src/mem.rs)
0xC044_0000    ├────────────────────┤
               │ zisklib ram        │  192 KB reserved (ZisK library scratch)
               │  0x30000 bytes     │  = ZISKLIB_RAM (core/src/mem.rs)
0xC047_0000    ├────────────────────┤
               │   .data            │
               │   .bss             │
               ├────────────────────┤ ← _bss_end, _heap_bottom (must stay below _pc_reach_end)
               │   heap ↓           │
               │                    │
               │                    │
               │                    │
0x1_4000_0000  └────────────────────┘ ← _heap_top

*/

SECTIONS
{
  .text : { *(.text.init) *(.text .text.* .gnu.linkonce.t.*)} >rom AT>rom :text

  . = ALIGN(8);
  PROVIDE(_global_pointer = .);
  .rodata : { KEEP(*(.rodata.zeg_build_flags)) *(.rodata .rodata.* .gnu.linkonce.r.*)} >rom AT>rom :rodata

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
  PROVIDE(_init_stack_bottom = .); /* alias for the start of the reserved stack region */
  . = . + _stack_size;
  PROVIDE(_init_stack_top = .); /* reserve 4M bytes for the initialisation stack */
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

  /* reserved space for the float library RAM (its data and stack) */

  .float_ram_data (NOLOAD) : {
    PROVIDE(_float_ram_data_start = .);
    . = . + _float_ram_data_size;
    PROVIDE(_float_ram_data_end = .);
  } >ram AT>ram :float_ram_data

  /* reserved space for the ZisK library RAM (scratch / variables) */

  .zisklib_ram_data (NOLOAD) : {
    PROVIDE(_zisklib_ram_data_start = .);
    . = . + _zisklib_ram_data_size;
    PROVIDE(_zisklib_ram_data_end = .);
  } >ram AT>ram :zisklib_ram_data

  .data : { *(.data .data.* .sdata .sdata.* .gnu.linkonce.d.* .gnu.linkonce.s.*) } >ram AT>ram :data

  .bss : {
    PROVIDE(_bss_start = .);
    *(.bss .bss.* .sbss .sbss.* .gnu.linkonce.b.* .gnu.linkonce.sb.*);
    PROVIDE(_bss_end = .); /* ... and one at the end */
  } >ram AT>ram :bss

  ASSERT(. <= _pc_reach_end, "guest .data/.bss end beyond the PC-relative reach of the code (2GiB from the ROM)")

  ASSERT(. < ORIGIN(ram) + _zisk_ram_size, "guest .data/.bss end beyond ZISK_RAM_SIZE")

  PROVIDE(_heap_bottom = .);
  PROVIDE(_heap_top = ORIGIN(ram) + _zisk_ram_size);
  PROVIDE(_heap_size = _heap_top - _heap_bottom);

  /* EF zkVM standard §9 names the allocator bounds `_heap_start` / `_heap_end`.
     Same two addresses as `_heap_bottom` / `_heap_top` above; added alongside them
     rather than renaming, so ziskos's allocator (which reads _heap_bottom /
     _heap_size) is untouched.

     Assigned UNCONDITIONALLY, not with PROVIDE: PROVIDE only materializes a symbol
     that some input object *references*, and an EF consumer discovers these by
     reading the ELF symbol table — it never references them at link time. Under
     PROVIDE they would be absent from .symtab for any guest that does not itself
     mention them, i.e. exactly the case the standard requires them for. The values
     are recomputed rather than aliased so they do not depend on the PROVIDEs above
     having materialized either. */
  _heap_start = .;
  _heap_end = ORIGIN(ram) + _zisk_ram_size;

  _end = .;
}
