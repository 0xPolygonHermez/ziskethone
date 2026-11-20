// pair_stats.inl — host-only profile of the opcode sequences evmone's cgoto
// dispatch executes (ZEG_PAIR_STATS; see dispatch.inl).
//
// At every dispatch it counts the triple (A, B, C): the opcode about to run
// and the next two opcodes in the code after it, each skipping its
// immediate. B and C are what would run next unless A or B jumps or halts,
// which is exactly the case a fused pair or triple entered at A covers. No
// fusion runs in this build, so every opcode is seen.
//
// At exit the counts are appended to the file named by $ZEG_PAIR_STATS_OUT as
// "A B C count" lines of hex opcodes (no file is written when it is unset).
#include <cstdio>
#include <cstdlib>
#include <unordered_map>

struct ZegPairStats
{
    std::unordered_map<uint32_t, uint64_t> triples;
    ~ZegPairStats()
    {
        const char* path = std::getenv("ZEG_PAIR_STATS_OUT");
        if (path == nullptr)
            return;
        if (FILE* f = std::fopen(path, "a"))
        {
            for (const auto& [k, n] : triples)
                std::fprintf(f, "%02x %02x %02x %llu\n", k >> 16, (k >> 8) & 0xff, k & 0xff,
                    static_cast<unsigned long long>(n));
            std::fclose(f);
        }
    }
};
inline ZegPairStats zeg_pair_stats;

inline void zeg_count_triple(const uint8_t* p) noexcept
{
    const uint8_t a = p[0];
    const uint8_t* q = p + 1 + instr::traits[a].immediate_size;
    const uint8_t b = q[0];
    // Executable code is padded with 33 STOPs, so q is in bounds. Past a
    // STOP (possibly padding) the next byte may not be: count it as STOP.
    const uint8_t c = b == OP_STOP ? 0 : q[1 + instr::traits[b].immediate_size];
    ++zeg_pair_stats.triples[(uint32_t{a} << 16) | (uint32_t{b} << 8) | c];
}

#define ZEG_DISPATCH()                         \
    do                                         \
    {                                          \
        zeg_count_triple(position.code_it);    \
        goto* cgoto_table[*position.code_it];  \
    } while (0)
#define ZEG_PAIR_INIT()
#define ZEG_PAIR_TARGETS
