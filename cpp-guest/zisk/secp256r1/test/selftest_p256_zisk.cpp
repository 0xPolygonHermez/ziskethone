// selftest_p256_zisk.cpp — on-emulator self-test of the secp256r1 (P-256) layer.
//
// Exercises the precompile + fcall backend (ZEG_ZISK): arith256_mod (0x802), the
// secp256r1 curve add/dbl precompiles (0x817/0x818), and the fn_inv (id 5) +
// msb_pos_256 (id 17) fcalls — by running ecdsa_verify on a valid vector and
// several tampered/boundary ones. Each check sets one result bit (slot 0; slot 1 =
// count). Built as p256_selftest.elf.
// Run: ziskemu -e p256_selftest.elf -i <8-byte len=0> -o out.

#include <cstdint>
#include <cstring>
#include "../p256.hpp"
#include "zeg/zisk_io.hpp"

using namespace zeg::r1;

static uint32_t g_results = 0;
static int g_bit = 0;
static void rec(bool ok) { if (ok) g_results |= (1u << g_bit); ++g_bit; }

// Valid P-256 vector 0 from gen_p256.py: {z, r, s, qx, qy}.
static const uint64_t Z[4]  = {0xC46F99EE646CE577ULL,0x6F2886D5BCCFCDC8ULL,0x7E3C5DE35CDA31FDULL,0xA7963B9C55EB1026ULL};
static const uint64_t R[4]  = {0x1184835CB143D339ULL,0xCE680B186B8D2767ULL,0xB2F06AD068ACB134ULL,0x811F0B9BD4BF465DULL};
static const uint64_t S[4]  = {0xBDF0B073A2AA1A63ULL,0xF40C57A1B93E0CA0ULL,0x0D7609386C940C7DULL,0xB1F3017BFC343B89ULL};
static const uint64_t QX[4] = {0x568C8F377B394AF4ULL,0xA4298C675484F318ULL,0x2D6033D86760B02EULL,0x3CF043F8BE20B6DCULL};
static const uint64_t QY[4] = {0x6118C4A556F5DEBCULL,0x2CD5535346EB7E51ULL,0x0876A3E36C1DEFA4ULL,0xF9FD04D9F0B27C40ULL};

int main() {
    uint64_t pk[8]; for (int i=0;i<4;++i){ pk[i]=QX[i]; pk[i+4]=QY[i]; }

    // valid signature accepted (full scalar-mul + curve precompiles + fn_inv fcall)
    rec(ecdsa_verify(pk, Z, R, S));                                  // bit0

    // tampered s rejected
    { uint64_t st[4]; std::memcpy(st,S,32); st[0]^=1; rec(!ecdsa_verify(pk, Z, R, st)); }  // bit1
    // tampered z rejected
    { uint64_t zt[4]; std::memcpy(zt,Z,32); zt[0]^=1; rec(!ecdsa_verify(pk, zt, R, S)); }  // bit2
    // off-curve pubkey rejected
    { uint64_t pkt[8]; std::memcpy(pkt,pk,64); pkt[4]^=1; rec(!ecdsa_verify(pkt, Z, R, S)); } // bit3
    // r = 0 rejected (range check)
    { uint64_t z0[4]={0,0,0,0}; rec(!ecdsa_verify(pk, Z, z0, S)); }  // bit4

    zeg::zisk::set_output_u32(0, g_results);
    zeg::zisk::set_output_u32(1, (uint32_t)g_bit);
    return 0;
}
