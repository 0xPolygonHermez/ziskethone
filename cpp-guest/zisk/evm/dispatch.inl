// dispatch.inl — the guest's hooks into evmone's cgoto dispatch (patch 06).
//
// baseline_execution.cpp includes this file inside its anonymous namespace,
// just above dispatch_cgoto, and expands four macros:
//   ZEG_PAIR_INIT()    at function entry;
//   ZEG_DISPATCH()     for every dispatch, in place of goto* cgoto_table[op];
//   ZEG_TRY_FUSE(OP)   at the top of each opcode's generic handler;
//   ZEG_PAIR_TARGETS   after the generic handlers, for extra labels.
// Whatever this file leaves undefined falls back to stock evmone.
//
//   ZEG_ZISK / ZEG_FUSE_TEST  the fusions (fused_dispatch.inl) and the
//                             opcode-pair dispatch (pair_dispatch.inl);
//   ZEG_PAIR_STATS            host-only profiling of the opcode sequences
//                             dispatch sees, to choose the pairs to fuse.
#pragma once

#if defined(ZEG_PAIR_STATS)
#include "pair_stats.inl"
#else
#include "fused_dispatch.inl"
#include "pair_dispatch.inl"
#endif
