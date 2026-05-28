#!/usr/bin/env python3
"""Wrap a raw ZEG0 input file for ziskemu.

ziskemu's input region layout (see zilkworm prover/guest_zisk/include/zisk_io.h):
  INPUT_ADDR + 0..8  : reserved 8-byte header prepended by ziskemu itself
  INPUT_ADDR + 8..16 : u64 LE length of the payload
  INPUT_ADDR + 16..  : payload bytes

The `-i` file we hand ziskemu is just [u64 LE payload_len][payload], padded to
an 8-byte boundary. ziskemu prepends its own 8-byte header on load, so the
guest's read_input() (which reads the length at INPUT_ADDR+8) sees it correctly.

Usage: wrap_input.py <raw.bin> <wrapped.bin>
"""
import sys
import struct

if len(sys.argv) != 3:
    sys.stderr.write("usage: wrap_input.py <raw.bin> <wrapped.bin>\n")
    sys.exit(1)

raw = open(sys.argv[1], "rb").read()
out = struct.pack("<Q", len(raw)) + raw
# Pad the whole frame to an 8-byte boundary.
pad = (-len(out)) % 8
out += b"\x00" * pad
open(sys.argv[2], "wb").write(out)
sys.stderr.write(f"wrapped {len(raw)} payload bytes -> {len(out)} frame bytes\n")
