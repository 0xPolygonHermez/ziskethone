/* Guest linker script for a ZisK prover built with its `ram_2gb` feature: the
 * heap (and the tx arena at its top) ends at the end of the 2 GB RAM window,
 * 0x1_4000_0000. Everything else is zisk.ld, which the linker finds through the
 * library search path (CMake passes -L for this directory). */
ZISK_RAM_SIZE = 0x80000000;
INCLUDE zisk.ld
