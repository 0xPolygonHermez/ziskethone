// zeg/chunked_vector.hpp — a vector that grows by adding chunks.
//
// A std::vector that doubles to n elements leaves its outgrown buffers behind
// under the guest's never-freeing bump allocator (zisk/runtime.cpp): ~2n
// element slots of dead memory on top of the n live ones, plus the slack of
// the last doubling. ChunkedVector never moves an element: it appends chunks
// whose sizes start at kFirst and double up to kMax, so it holds at most one
// partly used chunk and nothing dead. Shrinking (pop_back / truncate) keeps the
// chunks for the next push. Elements stay at the same address until destroyed.
//
// push_back, pop_back and back() work on a cursor into the last chunk, so they
// cost about what std::vector's do (the journal runs them on every call and
// revert); only operator[] and the iterators locate a chunk by index.
//
// The chunk table is a plain std::vector of pointers (8 bytes per chunk), so
// its own doubling is negligible. `Alloc` places the chunks and the table: the
// default heap, or zeg::TxArenaAllocator for per-transaction data, in which case
// release() must run before the arena reset (see zeg/tx_arena.hpp).

#pragma once

#include <cstddef>
#include <cstdint>
#include <iterator>
#include <memory>
#include <new>
#include <utility>
#include <vector>

namespace zeg {

template <class T, std::size_t kFirst, std::size_t kMax, class Alloc = std::allocator<T>>
class ChunkedVector {
    static_assert(kFirst > 0 && (kFirst & (kFirst - 1)) == 0, "kFirst: power of two");
    static_assert(kMax >= kFirst && (kMax & (kMax - 1)) == 0, "kMax: power of two");

    using Traits   = std::allocator_traits<Alloc>;
    using PtrAlloc = typename Traits::template rebind_alloc<T*>;

    static constexpr unsigned log2(std::size_t v) {
        unsigned r = 0;
        while (v > 1) { v >>= 1; ++r; }
        return r;
    }
    static constexpr unsigned    kFirstLog = log2(kFirst);
    static constexpr unsigned    kGrowing  = log2(kMax / kFirst);    // chunks before kMax
    static constexpr std::size_t kGrowCap  = kFirst * ((std::size_t{1} << kGrowing) - 1);

    // Chunk k holds min(kFirst << k, kMax) elements.
    static constexpr std::size_t chunk_cap(std::size_t k) {
        return k < kGrowing ? (kFirst << k) : kMax;
    }
    // Element i -> (chunk, offset).
    static std::pair<std::size_t, std::size_t> locate(std::size_t i) noexcept {
        if (i < kGrowCap) {
            const std::size_t q = (i >> kFirstLog) + 1;  // chunk k covers q in [2^k, 2^(k+1))
            const auto k = static_cast<std::size_t>(63 - __builtin_clzll(q));
            return {k, i - kFirst * ((std::size_t{1} << k) - 1)};
        }
        const std::size_t j = i - kGrowCap;
        return {kGrowing + j / kMax, j % kMax};
    }

    std::vector<T*, PtrAlloc> chunks_;
    std::size_t               size_ = 0;
    // The cursor: chunk cur_ holds the last elements, [begin_, end_), and ends
    // at limit_; the chunks before it are full. It may be empty after a
    // pop_back (the last element then ends chunk cur_ - 1). All null while the
    // table is empty.
    std::size_t               cur_   = 0;
    T*                        begin_ = nullptr;
    T*                        end_   = nullptr;
    T*                        limit_ = nullptr;
    Alloc                     alloc_{};

    T* slot(std::size_t i) const noexcept {
        const auto [k, off] = locate(i);
        return chunks_[k] + off;
    }
    void enter(std::size_t k, T* end) noexcept {
        cur_   = k;
        begin_ = chunks_[k];
        limit_ = begin_ + chunk_cap(k);
        end_   = end;
    }
    void reset_cursor() noexcept {
        cur_   = 0;
        begin_ = end_ = limit_ = nullptr;
    }
    void steal(ChunkedVector& o) noexcept {
        chunks_ = std::move(o.chunks_);
        size_   = o.size_;
        cur_    = o.cur_;
        begin_  = o.begin_;
        end_    = o.end_;
        limit_  = o.limit_;
        o.chunks_.clear();
        o.size_ = 0;
        o.reset_cursor();
    }

public:
    ChunkedVector() = default;
    ChunkedVector(const ChunkedVector&) = delete;
    ChunkedVector& operator=(const ChunkedVector&) = delete;
    ChunkedVector(ChunkedVector&& o) noexcept : alloc_(o.alloc_) { steal(o); }
    ChunkedVector& operator=(ChunkedVector&& o) noexcept {
        if (this != &o) {
            release();
            steal(o);
        }
        return *this;
    }
    ~ChunkedVector() { release(); }

    std::size_t size() const noexcept { return size_; }
    bool        empty() const noexcept { return size_ == 0; }

    T&       operator[](std::size_t i) noexcept { return *slot(i); }
    const T& operator[](std::size_t i) const noexcept { return *slot(i); }
    T& back() noexcept {
        return end_ != begin_ ? end_[-1] : chunks_[cur_ - 1][chunk_cap(cur_ - 1) - 1];
    }
    const T& back() const noexcept {
        return end_ != begin_ ? end_[-1] : chunks_[cur_ - 1][chunk_cap(cur_ - 1) - 1];
    }

    template <class... Args>
    T& emplace_back(Args&&... args) {
        if (end_ == limit_) {  // chunk cur_ is full (or there is none): the next one
            const std::size_t k = begin_ == nullptr ? 0 : cur_ + 1;
            if (k == chunks_.size()) {
                chunks_.push_back(Traits::allocate(alloc_, chunk_cap(k)));
            }
            enter(k, chunks_[k]);
        }
        T* p = ::new (static_cast<void*>(end_)) T(std::forward<Args>(args)...);
        ++end_;
        ++size_;
        return *p;
    }
    void push_back(T&& v) { emplace_back(std::move(v)); }
    void push_back(const T& v) { emplace_back(v); }

    void pop_back() noexcept {
        if (end_ == begin_) {  // chunk cur_ is empty: back to the full one before it
            enter(cur_ - 1, chunks_[cur_ - 1] + chunk_cap(cur_ - 1));
        }
        --end_;
        --size_;
        std::destroy_at(end_);
    }

    // Destroy the elements from `n` on; the chunks stay for reuse.
    void truncate(std::size_t n) noexcept {
        while (size_ > n) pop_back();
    }

    // Destroy everything and give the chunks and the table back.
    void release() noexcept {
        truncate(0);
        for (std::size_t k = 0; k < chunks_.size(); ++k) {
            Traits::deallocate(alloc_, chunks_[k], chunk_cap(k));
        }
        decltype(chunks_){}.swap(chunks_);
        reset_cursor();
    }

    template <bool kConst>
    class Iter {
        using Owner = std::conditional_t<kConst, const ChunkedVector, ChunkedVector>;
        Owner*      v_ = nullptr;
        std::size_t i_ = 0;

    public:
        using iterator_category = std::forward_iterator_tag;
        using value_type        = T;
        using difference_type   = std::ptrdiff_t;
        using pointer           = std::conditional_t<kConst, const T*, T*>;
        using reference         = std::conditional_t<kConst, const T&, T&>;

        Iter() = default;
        Iter(Owner* v, std::size_t i) : v_(v), i_(i) {}
        reference operator*() const noexcept { return (*v_)[i_]; }
        pointer   operator->() const noexcept { return &(*v_)[i_]; }
        Iter& operator++() noexcept { ++i_; return *this; }
        Iter  operator++(int) noexcept { Iter t = *this; ++i_; return t; }
        bool  operator==(const Iter& o) const noexcept { return i_ == o.i_; }
        bool  operator!=(const Iter& o) const noexcept { return i_ != o.i_; }
    };
    using iterator       = Iter<false>;
    using const_iterator = Iter<true>;

    iterator       begin() noexcept { return {this, 0}; }
    iterator       end() noexcept { return {this, size_}; }
    const_iterator begin() const noexcept { return {this, 0}; }
    const_iterator end() const noexcept { return {this, size_}; }
};

}  // namespace zeg
