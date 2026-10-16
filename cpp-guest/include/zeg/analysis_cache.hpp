// zeg/analysis_cache.hpp — fixed-size, reusable cache of EVM code analyses.
//
// Each distinct executed bytecode needs a JUMPDEST analysis (evmone: a padded
// code copy + bitmap, ~27 KiB for a 24 KiB contract; zevm: just the bitmap,
// ~3 KiB). Before this cache they were allocated once per distinct bytecode and
// retained for the whole block; under the guest's never-freeing bump allocator
// (zisk/runtime.cpp) a block executing thousands of distinct max-size contracts
// accumulated hundreds of MB and OOM-halted the prover.
//
// This cache draws every analysis from ONE arena allocated at construction and
// reuses slots by LRU eviction, so block memory is bounded regardless of how
// many distinct contracts run. An analysis referenced by a live call frame is
// "pinned" (refcount > 0) and never evicted — the interpreter holds raw
// pointers into it. The arena is sized above the maximum simultaneously-pinned
// set (<= call depth), so eviction never has to fail a valid block; honest
// blocks (<=~350 distinct contracts) never evict. Backend-agnostic: it drives
// the evmc2 `prepare` with a slot buffer and both backends lay their analysis
// inside it.

#pragma once

#include <cstddef>
#include <cstdint>

#include "zeg/evmc2.h"
#include "zeg/fatal.hpp"

namespace zeg {

class AnalysisCache {
public:
    // `arena_bytes` total reservation; `slot_bytes` = the backend's maximum
    // single-analysis size (so any contract fits any slot — no fragmentation,
    // and slots never move, which pinning requires).
    AnalysisCache(evmc2_vm* vm, std::size_t arena_bytes, std::size_t slot_bytes)
        : vm_(vm), slot_bytes_(slot_bytes), num_slots_(arena_bytes / slot_bytes) {
        if (num_slots_ == 0) {
            zeg::fatal("analysis cache: arena smaller than one slot");
        }
        arena_ = new uint8_t[num_slots_ * slot_bytes_];
        meta_ = new Slot[num_slots_];
        for (std::size_t i = 0; i < num_slots_; ++i) {
            meta_[i].next_free =
                (i + 1 < num_slots_) ? static_cast<int64_t>(i + 1) : -1;
        }
        free_head_ = 0;
        lru_head_ = lru_tail_ = -1;
    }

    ~AnalysisCache() {
        delete[] arena_;   // no-op under the bump allocator; frees on the host
        delete[] meta_;
    }

    AnalysisCache(const AnalysisCache&) = delete;
    AnalysisCache& operator=(const AnalysisCache&) = delete;

    // Return (preparing on miss) the analysis for `code`, and pin it for the
    // duration of the frame that is about to run. `owner` points at the
    // Contract's cached-handle field; it is set on prepare and nulled on evict.
    evmc2_pre_execution* acquire(evmc2_pre_execution** owner, const uint8_t* code,
                                 std::size_t code_size) {
        if (*owner != nullptr) {  // hit: still resident
            const int64_t i = slot_of(*owner);
            ++meta_[i].pin;
            lru_touch(i);
            return *owner;
        }
        const int64_t i = alloc_slot();  // miss: free slot or evict an unpinned one
        uint8_t* buf = arena_ + static_cast<std::size_t>(i) * slot_bytes_;
        evmc2_pre_execution* h =
            vm_->prepare(&vm_->base, code, code_size, buf, slot_bytes_);
        // Backends that use the slot return a handle inside it (== buf). A null
        // return would mean an empty-code prepare, which callers never cache.
        meta_[i].owner = owner;
        meta_[i].pin = 1;
        *owner = h;
        lru_push_front(i);
        return h;
    }

    // Drop one pin taken by acquire(); the entry stays cached until evicted.
    void release(evmc2_pre_execution* handle) noexcept {
        if (handle == nullptr) return;
        const int64_t i = slot_of(handle);
        if (meta_[i].pin > 0) --meta_[i].pin;
    }

    // Block teardown: clear every owner's cached handle; keep the arena.
    void reset() noexcept {
        for (std::size_t i = 0; i < num_slots_; ++i) {
            if (meta_[i].owner != nullptr) {
                *meta_[i].owner = nullptr;
                meta_[i].owner = nullptr;
            }
            meta_[i].pin = 0;
            meta_[i].in_lru = false;
            meta_[i].lru_prev = meta_[i].lru_next = -1;
            meta_[i].next_free =
                (i + 1 < num_slots_) ? static_cast<int64_t>(i + 1) : -1;
        }
        free_head_ = 0;
        lru_head_ = lru_tail_ = -1;
    }

private:
    struct Slot {
        evmc2_pre_execution** owner = nullptr;  // &Contract::analysis, or null when free
        uint32_t pin = 0;
        bool in_lru = false;
        int64_t lru_prev = -1, lru_next = -1;
        int64_t next_free = -1;
    };

    int64_t slot_of(evmc2_pre_execution* h) const noexcept {
        return static_cast<int64_t>(
            (reinterpret_cast<uint8_t*>(h) - arena_) / slot_bytes_);
    }

    int64_t alloc_slot() {
        if (free_head_ >= 0) {  // never-used slot
            const int64_t i = free_head_;
            free_head_ = meta_[i].next_free;
            meta_[i].next_free = -1;
            return i;
        }
        // Evict the least-recently-used entry that no live frame pins.
        for (int64_t i = lru_tail_; i >= 0; i = meta_[i].lru_prev) {
            if (meta_[i].pin == 0) {
                lru_remove(i);
                if (meta_[i].owner != nullptr) {
                    *meta_[i].owner = nullptr;
                    meta_[i].owner = nullptr;
                }
                return i;
            }
        }
        zeg::fatal("analysis cache: all slots pinned (arena too small for depth)");
        return -1;  // unreachable
    }

    void lru_push_front(int64_t i) noexcept {
        meta_[i].lru_prev = -1;
        meta_[i].lru_next = lru_head_;
        if (lru_head_ >= 0) meta_[lru_head_].lru_prev = i;
        else lru_tail_ = i;
        lru_head_ = i;
        meta_[i].in_lru = true;
    }
    void lru_remove(int64_t i) noexcept {
        if (!meta_[i].in_lru) return;
        if (meta_[i].lru_prev >= 0) meta_[meta_[i].lru_prev].lru_next = meta_[i].lru_next;
        else lru_head_ = meta_[i].lru_next;
        if (meta_[i].lru_next >= 0) meta_[meta_[i].lru_next].lru_prev = meta_[i].lru_prev;
        else lru_tail_ = meta_[i].lru_prev;
        meta_[i].in_lru = false;
        meta_[i].lru_prev = meta_[i].lru_next = -1;
    }
    void lru_touch(int64_t i) noexcept { lru_remove(i); lru_push_front(i); }

    evmc2_vm* vm_;
    std::size_t slot_bytes_;
    std::size_t num_slots_;
    uint8_t* arena_ = nullptr;
    Slot* meta_ = nullptr;
    int64_t free_head_ = -1;
    int64_t lru_head_ = -1, lru_tail_ = -1;
};

}  // namespace zeg
