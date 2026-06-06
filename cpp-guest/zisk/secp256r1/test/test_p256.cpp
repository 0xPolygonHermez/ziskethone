// test_p256.cpp — host test of secp256r1/P-256 ECDSA verify vs evmone (EVM ref).
//   c++ -std=c++20 -O2 -I.. -I<evmone>/lib/evmone_precompiles -I<evmone>/include \
//       -I<intx>/include test_p256.cpp <evmone>/lib/evmone_precompiles/secp256r1.cpp -o /tmp/t && /tmp/t
// Software backend. Differential: our zeg::r1::ecdsa_verify must agree with
// evmmax::secp256r1::verify on valid (pure-python-signed) vectors, tampered ones,
// random inputs, and boundary cases.

#include <cstdio>
#include <cstdint>
#include <cstring>
#include "secp256r1.hpp"      // evmone evmmax::secp256r1::verify
#include "../p256.hpp"        // zeg::r1

namespace ev = evmmax::secp256r1;
static int g_fail = 0;
static void check(bool ok, const char* n){ std::printf("%s %s\n", ok?"ok  ":"FAIL", n); if(!ok)++g_fail; }

static intx::uint256 u256(const uint64_t v[4]) {
    return intx::uint256{v[0]}|(intx::uint256{v[1]}<<64)|(intx::uint256{v[2]}<<128)|(intx::uint256{v[3]}<<192);
}
static ethash::hash256 h256(const uint64_t z[4]) {  // limbs(LE) → 32-byte BE
    ethash::hash256 h{};
    for (int i=0;i<4;++i) for (int j=0;j<8;++j) h.bytes[i*8+j] = (uint8_t)(z[3-i] >> (8*(7-j)));
    return h;
}
// our verify from the 5 limb arrays.
static bool my_verify(const uint64_t z[4], const uint64_t r[4], const uint64_t s[4],
                      const uint64_t qx[4], const uint64_t qy[4]) {
    uint64_t pk[8]; for(int i=0;i<4;++i){pk[i]=qx[i];pk[i+4]=qy[i];}
    return zeg::r1::ecdsa_verify(pk, z, r, s);
}
// evmone verify from the 5 limb arrays.
static bool ev_verify(const uint64_t z[4], const uint64_t r[4], const uint64_t s[4],
                      const uint64_t qx[4], const uint64_t qy[4]) {
    return ev::verify(h256(z), u256(r), u256(s), u256(qx), u256(qy));
}

// {z, r, s, qx, qy}, each 4 limbs LE — valid signatures from gen_p256.py.
static const uint64_t VEC[6][5][4] = {
  {{0xC46F99EE646CE577ULL,0x6F2886D5BCCFCDC8ULL,0x7E3C5DE35CDA31FDULL,0xA7963B9C55EB1026ULL},{0x1184835CB143D339ULL,0xCE680B186B8D2767ULL,0xB2F06AD068ACB134ULL,0x811F0B9BD4BF465DULL},{0xBDF0B073A2AA1A63ULL,0xF40C57A1B93E0CA0ULL,0x0D7609386C940C7DULL,0xB1F3017BFC343B89ULL},{0x568C8F377B394AF4ULL,0xA4298C675484F318ULL,0x2D6033D86760B02EULL,0x3CF043F8BE20B6DCULL},{0x6118C4A556F5DEBCULL,0x2CD5535346EB7E51ULL,0x0876A3E36C1DEFA4ULL,0xF9FD04D9F0B27C40ULL}},
  {{0x1BA5571DC43B91A3ULL,0x14FC3BB9A313A624ULL,0xFE9DEB66E12B0549ULL,0x894DD2487FEF2022ULL},{0x96831491775D34B6ULL,0x1F7DEEA108AA500FULL,0x9B2C26A2FF26F94DULL,0x2789A8E8E80B0138ULL},{0xE3BE93D78D2BB1E4ULL,0xDBE3B354B6F3D0A5ULL,0x422F91D272BEC0C2ULL,0x164CC6E93F632217ULL},{0x71E21FD991BDF5E8ULL,0x3B50794B2B9B32C9ULL,0xAE4D76145D164E8AULL,0x1B8368C1375CFEAAULL},{0x54BEA90805C5A61EULL,0x6DEF861BF4933272ULL,0x9492F42DE9FBBC4EULL,0x2B1D422191A3E4ADULL}},
  {{0x9240AA1E74FAC20FULL,0x6BBEA1326886BBC0ULL,0xD0BF919BEE0052D5ULL,0xD1AB6A1A4DEFFB5EULL},{0xCE00F624A361008FULL,0xE91347670ADD3AAEULL,0x30FA29E1FE788896ULL,0x2ACAD06E74629C09ULL},{0x10639DFA9145D5C2ULL,0xC355134762B6E4FBULL,0x097690EB74BAB769ULL,0x8454A2BA5F532CA1ULL},{0xDAC58D65A4D30E8DULL,0xE2758C6F8F8B155EULL,0xA8D7C213C303AC4CULL,0x902E5EDCB07D3DC3ULL},{0x8EF5482E08ABB413ULL,0xC8F28990C907EB7FULL,0x89873B64F008CF3FULL,0x081BE56905449687ULL}},
  {{0x194DEC7CC9DA82BBULL,0x38C869B09500CA9CULL,0x0DF20621CEC646A1ULL,0x5A3FD7E16B85FDDAULL},{0xD0D804F242B70A50ULL,0x5371C0B3EF07DFD0ULL,0xC2FF0C9F3350D6CEULL,0x15B92F4B6B1493B5ULL},{0x464B6FA61FEE2EDAULL,0x5EF284A633D75FCFULL,0x250E915146F4C210ULL,0x3A1E1927F67A62ACULL},{0xD32EBB1CE23C8A3BULL,0x2C4F7D5EF79F43AFULL,0xAB4D6621A6AB2B89ULL,0xE9FAB557452C18CEULL},{0x01E7662CCC3DA71EULL,0x8BADF5B8A04228ADULL,0xCE691BA6C7F07DC2ULL,0x11BC849FAB5A8134ULL}},
  {{0x636BC032E1A91FA7ULL,0xE3C872652758CEB8ULL,0xAF1FAB45E36D4CADULL,0xBA93ADF4E786C396ULL},{0x25CD58C733409AA9ULL,0x3168CFA37358CE52ULL,0x0285557679A1F607ULL,0xC5E84B74AD164F92ULL},{0x201B910EE9072C01ULL,0x981A0B625A367084ULL,0xE371D96D1B57AF7DULL,0xC7D59481EB62A7E4ULL},{0xE8D282E606DA3F7DULL,0x4CA653C655FE4BA0ULL,0xDA09B90FD44F813AULL,0x8E03CE63EAC65EDCULL},{0xC9FCF14F7531D0FBULL,0xEE056B29AA40325AULL,0xF95931717BF29260ULL,0x4CA92A89A89278A2ULL}},
  {{0x7DC35B543DBF24D3ULL,0xFC749616BB810414ULL,0x5678BEA1907610F9ULL,0x941A74E8CBC12892ULL},{0x927961F88865ACE6ULL,0xC4883452E3AD013DULL,0x26068509EEE9E417ULL,0xF0221C66F55CD1C6ULL},{0x38D12C558001B5F5ULL,0x1E0DB2CC5A234FB3ULL,0x363EE22D48DAD113ULL,0xCABEC72984BF56B1ULL},{0xA78F62C8CBE03FC0ULL,0x456DE419D0151F8FULL,0xF0CA85F6C6DE2A6EULL,0x934BF64B3A0C4EC9ULL},{0x7168B55698C30693ULL,0xA7659A6C2BBBA0A1ULL,0xA19AFEAE31C42FA0ULL,0x76DE0BBB87D200DDULL}},
};

int main() {
    bool valid=true, diff=true;
    for (int i=0;i<6;++i) {
        const uint64_t *z=VEC[i][0], *r=VEC[i][1], *s=VEC[i][2], *qx=VEC[i][3], *qy=VEC[i][4];
        bool mv=my_verify(z,r,s,qx,qy), ev=ev_verify(z,r,s,qx,qy);
        if (!(mv && ev)) valid=false;
        if (mv != ev) diff=false;
        // tamper s (+1): both must reject and agree
        uint64_t st[4]; std::memcpy(st,s,32); st[0]^=1;
        if (my_verify(z,r,st,qx,qy) != ev_verify(z,r,st,qx,qy)) diff=false;
        if (my_verify(z,r,st,qx,qy)) valid=false;
        // tamper z (+1)
        uint64_t zt[4]; std::memcpy(zt,z,32); zt[0]^=1;
        if (my_verify(zt,r,s,qx,qy) != ev_verify(zt,r,s,qx,qy)) diff=false;
        // off-curve pubkey (qy+1)
        uint64_t qyt[4]; std::memcpy(qyt,qy,32); qyt[0]^=1;
        if (my_verify(z,r,s,qx,qyt) != ev_verify(z,r,s,qx,qyt)) diff=false;
        if (my_verify(z,r,s,qx,qyt)) valid=false;
    }
    check(valid, "valid sigs accepted; tampered rejected");
    check(diff,  "our verify == evmone on valid/tampered/off-curve");

    // boundary cases (differential), using vec 0's pubkey
    const uint64_t *qx=VEC[0][3], *qy=VEC[0][4], *z=VEC[0][0];
    const uint64_t Z[4]={0,0,0,0};
    const uint64_t Nlimb[4]={0xF3B9CAC2FC632551ULL,0xBCE6FAADA7179E84ULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFF00000000ULL};
    const uint64_t Plimb[4]={0xFFFFFFFFFFFFFFFFULL,0x00000000FFFFFFFFULL,0,0xFFFFFFFF00000001ULL};
    bool bnd=true;
    auto cmp=[&](const uint64_t*zz,const uint64_t*rr,const uint64_t*ss,const uint64_t*xx,const uint64_t*yy){
        if (my_verify(zz,rr,ss,xx,yy)!=ev_verify(zz,rr,ss,xx,yy)) bnd=false; };
    cmp(z, Z, VEC[0][2], qx, qy);          // r = 0
    cmp(z, VEC[0][1], Z, qx, qy);          // s = 0
    cmp(z, Nlimb, VEC[0][2], qx, qy);      // r = n  (>= n)
    cmp(z, VEC[0][1], Nlimb, qx, qy);      // s = n
    cmp(z, VEC[0][1], VEC[0][2], Plimb, qy); // qx = p (>= p)
    cmp(z, VEC[0][1], VEC[0][2], Z, Z);    // Q = O
    check(bnd, "boundary cases == evmone (r/s=0/n, qx=p, Q=O)");

    std::printf(g_fail ? "\n%d FAILED\n" : "\nALL PASS\n", g_fail);
    return g_fail ? 1 : 0;
}
