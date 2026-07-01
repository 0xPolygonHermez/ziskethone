// secp256k1.cpp — secp256k1 ECDSA recover, two implementations of the same ABI
// selected by target (ZEG_ZISK):
//
//   ZisK guest (ZEG_ZISK) : in-circuit recover over ZisK precompiles
//                           (arith256_mod 0x802, secp256k1_add/dbl 0x803/0x804)
//                           + verified fcall hints (FN_INV, FP_SQRT,
//                           MSB_POS_256) — a faithful port of ziskos's
//                           `zisklib`. `-DZEG_SECP256K1_SW` swaps the low-level
//                           primitives for a portable software baseline (same
//                           result, no accelerators); both run on ziskemu.
//   host (!ZEG_ZISK)      : superaccelerated — delegates to evmone's
//                           evmmax::secp256k1::secp256k1_ecdsa_recover (intx,
//                           projective coords). The host only needs a correct
//                           fast answer (it proves nothing), and evmone is the
//                           reference implementation, so it doubles as the
//                           differential oracle for the ZisK path.
//
// Public ABI (see zeg/zisk_crypto.hpp):
//   int secp256k1_ecdsa_recover(z, r, s, recid, pubkey)
//       full ECDSA public-key recovery — every signer derivation in the guest
//       (tx senders, EIP-7702 auth signers, the EVM ECRECOVER precompile) goes
//       through it via zeg::ecrecover_address. Limbs: uint64_t[4] little-endian
//       (limb[0] = low 64 bits); points are uint64_t[8] = x[4] || y[4].

#include <cstdint>

#if !defined(ZEG_ZISK)
// ===========================================================================
// Host: delegate to evmone's reference recover.
// ===========================================================================
#include <evmone_precompiles/secp256k1.hpp>

namespace {
// LE limbs (uint64_t[4], limb[0] = low) <-> 32 big-endian bytes, for the evmone
// boundary (it takes/returns big-endian).
inline void limbs_to_be(const uint64_t l[4], uint8_t be[32]) {
    for (int i = 0; i < 4; ++i) {
        const uint64_t w = l[3 - i];
        for (int j = 0; j < 8; ++j) be[i * 8 + j] = static_cast<uint8_t>(w >> (8 * (7 - j)));
    }
}
inline void be_to_limbs(const uint8_t be[32], uint64_t l[4]) {
    for (int i = 0; i < 4; ++i) {
        uint64_t w = 0;
        for (int j = 0; j < 8; ++j) w = (w << 8) | be[i * 8 + j];
        l[3 - i] = w;
    }
}
}  // namespace

extern "C" int secp256k1_ecdsa_recover(const uint64_t* z, const uint64_t* r,
                                       const uint64_t* s, unsigned recid,
                                       uint64_t* pubkey) {
    uint8_t zb[32], rb[32], sb[32];
    limbs_to_be(z, zb);
    limbs_to_be(r, rb);
    limbs_to_be(s, sb);
    // evmone validates r,s in [1,n-1] and returns nullopt when no point exists —
    // identical precompile semantics to the ZisK path below.
    const auto pt = evmmax::secp256k1::secp256k1_ecdsa_recover(zb, rb, sb, recid != 0);
    if (!pt.has_value())
        return 1;  // not recoverable
    uint8_t pk[64];
    pt->to_bytes(pk);  // x || y, 64 big-endian bytes (Montgomery -> normal)
    be_to_limbs(pk, pubkey);
    be_to_limbs(pk + 32, pubkey + 4);
    return 0;
}

#else  // ===================== ZisK guest =====================================

namespace {

typedef uint64_t u64;

// ---- curve constants (little-endian limbs) --------------------------------
const u64 N[4]  = {0xBFD25E8CD0364141ULL, 0xBAAEDCE6AF48A03BULL,
                   0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL};
const u64 GX[4] = {0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL,
                   0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL};
const u64 GY[4] = {0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL,
                   0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL};
const u64 G[8]  = {GX[0], GX[1], GX[2], GX[3], GY[0], GY[1], GY[2], GY[3]};
const u64 ZERO[4] = {0, 0, 0, 0};
const u64 ONE[4]  = {1, 0, 0, 0};
const u64 TWO[4]  = {2, 0, 0, 0};

// Field prime P = 2^256 - 2^32 - 977, the curve constant b = 7, and the modular
// square-root exponent (P+1)/4 (valid because P ≡ 3 mod 4; used only by the
// software fp_sqrt_hint — the ZisK backend gets the root from the fp_sqrt
// fcall). Used by ecrecover to reconstruct R.y from R.x. (verify needs none of
// these — it works mod N and lets the EC precompiles handle the field
// internally.)
const u64 P[4]    = {0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL,
                     0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL};
const u64 SEVEN[4] = {7, 0, 0, 0};
const u64 P_PLUS_1_DIV_4[4] = {0xFFFFFFFFBFFFFF0CULL, 0xFFFFFFFFFFFFFFFFULL,
                               0xFFFFFFFFFFFFFFFFULL, 0x3FFFFFFFFFFFFFFFULL};
// First quadratic non-residue of Fp — must match the ZisK fp_sqrt fcall's NQR
// (zisklib lib/secp256k1/constants.rs): on "no root" the fcall's witness is
// sqrt(alpha·NQR), which the guest verifies against alpha·NQR3.
const u64 NQR3[4] = {3, 0, 0, 0};

const u64 N_MINUS_ONE[4] = {0xBFD25E8CD0364140ULL, 0xBAAEDCE6AF48A03BULL,
                            0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL};
const u64 P_MINUS_ONE[4] = {0xFFFFFFFEFFFFFC2EULL, 0xFFFFFFFFFFFFFFFFULL,
                            0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL};

// GLV endomorphism constants (zisklib lib/secp256k1/constants.rs). φ:(x,y)↦(β·x,y)
// acts as [λ] on the group, so k·P = k1·P + k2·φ(P) with |k1|,|k2| < 2^128.
const u64 BETA[4]   = {0xC1396C28719501EEULL, 0x9CF0497512F58995ULL,
                       0x6E64479EAC3434E9ULL, 0x7AE96A2B657C0710ULL};
const u64 LAMBDA[4] = {0xDF02967C1B23BD72ULL, 0x122E22EA20816678ULL,
                       0xA5261C028812645AULL, 0x5363AD4CC05C30E0ULL};
const u64 G_NEG_Y[4] = {0x63B82F6F04EF2777ULL, 0x02E84BB7597AABE6ULL,
                        0xA25B0403F1EEF757ULL, 0xB7C52588D95C3B9AULL};
const u64 G_PHI_X[4] = {0xA7BBA04400B88FCBULL, 0x872844067F15E98DULL,
                        0xAB0102B696902325ULL, 0xBCACE2E99DA01887ULL};
// φ(G) = (G_PHI_X, G_Y) and -φ(G) = (G_PHI_X, G_NEG_Y).
const u64 G_PHI[8]     = {G_PHI_X[0],G_PHI_X[1],G_PHI_X[2],G_PHI_X[3], GY[0],GY[1],GY[2],GY[3]};
const u64 G_PHI_NEG[8] = {G_PHI_X[0],G_PHI_X[1],G_PHI_X[2],G_PHI_X[3], G_NEG_Y[0],G_NEG_Y[1],G_NEG_Y[2],G_NEG_Y[3]};
const u64 G_NEG[8]     = {GX[0],GX[1],GX[2],GX[3], G_NEG_Y[0],G_NEG_Y[1],G_NEG_Y[2],G_NEG_Y[3]};

// Abort used when a verified hint turns out wrong — those paths must never
// execute on a valid run. The shared trap from runtime.cpp (marchid-dispatched
// unimp / magic write) fails the run/proof immediately — trapping beats an
// infinite loop, which would spin to the emulator's step ceiling before failing.
extern "C" [[noreturn]] void zeg_zisk_halt();

inline void cp4(u64 d[4], const u64 s[4]) { d[0]=s[0]; d[1]=s[1]; d[2]=s[2]; d[3]=s[3]; }
inline void cp8(u64 d[8], const u64 s[8]) { for (int i=0;i<8;++i) d[i]=s[i]; }
inline bool eq4(const u64 a[4], const u64 b[4]) {
    return a[0]==b[0] && a[1]==b[1] && a[2]==b[2] && a[3]==b[3];
}
inline bool is_zero4(const u64 a[4]) { return a[0]==0&&a[1]==0&&a[2]==0&&a[3]==0; }
inline bool lt4(const u64 a[4], const u64 b[4]) {  // a < b
    for (int i=3;i>=0;--i) { if (a[i]<b[i]) return true; if (a[i]>b[i]) return false; }
    return false;
}

} // namespace

// ===========================================================================
// Backend: low-level primitives — arith256_mod, ec_add, ec_dbl, fn_inv_hint,
// msb_pos256. Either ZisK precompiles/fcalls (default) or portable software.
// ===========================================================================
#if defined(ZEG_SECP256K1_SW)
namespace {


// ---- portable 256-bit modular arithmetic ----------------------------------
inline void mul256(const u64 a[4], const u64 b[4], u64 out[8]) {
    for (int i=0;i<8;++i) out[i]=0;
    for (int i=0;i<4;++i) {
        u64 carry=0;
        for (int j=0;j<4;++j) {
            unsigned __int128 t = (unsigned __int128)a[i]*b[j] + out[i+j] + carry;
            out[i+j] = (u64)t;
            carry = (u64)(t>>64);
        }
        out[i+4] += carry;
    }
}
inline bool ge_512_256(const u64 r[8], const u64 m[4]) {
    for (int i=7;i>=4;--i) if (r[i]) return true;
    for (int i=3;i>=0;--i) { if (r[i]>m[i]) return true; if (r[i]<m[i]) return false; }
    return true;  // equal
}
inline void sub_m_512(u64 r[8], const u64 m[4]) {
    unsigned __int128 borrow=0;
    for (int i=0;i<8;++i) {
        u64 mi = (i<4)?m[i]:0;
        unsigned __int128 t = (unsigned __int128)r[i] - mi - borrow;
        r[i] = (u64)t;
        borrow = (t>>64)&1;
    }
}
inline void mod512(const u64 num[8], const u64 m[4], u64 out[4]) {
    u64 r[8] = {0,0,0,0,0,0,0,0};
    for (int i=511;i>=0;--i) {
        u64 carry=0;
        for (int k=0;k<8;++k) { u64 nx=(r[k]>>63)&1; r[k]=(r[k]<<1)|carry; carry=nx; }
        r[0] |= (num[i>>6]>>(i&63)) & 1ULL;
        if (ge_512_256(r,m)) sub_m_512(r,m);
    }
    out[0]=r[0]; out[1]=r[1]; out[2]=r[2]; out[3]=r[3];
}
// d = (a*b + c) mod m
inline void arith256_mod(const u64 a[4], const u64 b[4], const u64 c[4],
                         const u64 m[4], u64 d[4]) {
    u64 t[8]; mul256(a,b,t);
    unsigned __int128 carry=0;
    for (int i=0;i<8;++i) { u64 ci=(i<4)?c[i]:0; unsigned __int128 s=(unsigned __int128)t[i]+ci+carry; t[i]=(u64)s; carry=s>>64; }
    mod512(t,m,d);
}
inline void modmul(const u64 a[4], const u64 b[4], const u64 m[4], u64 o[4]) { arith256_mod(a,b,ZERO,m,o); }
inline void modpow(const u64 base[4], const u64 e[4], const u64 m[4], u64 o[4]) {
    u64 res[4]; cp4(res,ONE);
    for (int i=255;i>=0;--i) {
        u64 t[4]; modmul(res,res,m,t); cp4(res,t);
        if ((e[i>>6]>>(i&63)) & 1ULL) { modmul(res,base,m,t); cp4(res,t); }
    }
    cp4(o,res);
}
inline void inv_mod(const u64 a[4], const u64 m[4], u64 o[4]) {  // a^(m-2) mod m
    u64 e[4]; cp4(e,m); e[0]-=2;  // m[0] is odd, no borrow
    modpow(a,e,m,o);
}
inline void modsub_p(const u64 a[4], const u64 b[4], u64 o[4]) { // (a-b) mod P
    u64 negb[4]; unsigned __int128 borrow=0;
    for (int i=0;i<4;++i){ unsigned __int128 t=(unsigned __int128)P[i]-b[i]-borrow; negb[i]=(u64)t; borrow=(t>>64)&1; }
    arith256_mod(a,ONE,negb,P,o);
}

// ---- EC point ops (affine, software) --------------------------------------
void ec_add(u64 p1[8], const u64 p2[8]) {
    const u64 *x1=p1, *y1=p1+4, *x2=p2, *y2=p2+4;
    if (eq4(x1,x2)) {
        if (!eq4(y1,y2)) { for(int i=0;i<8;++i) p1[i]=0; return; }  // p + (-p) = O
        u64 xx[4]; modmul(x1,x1,P,xx);
        const u64 THREE[4]={3,0,0,0};
        u64 thr[4]; modmul(xx,THREE,P,thr);
        u64 dy[4]; arith256_mod(y1,TWO,ZERO,P,dy);
        u64 inv[4]; inv_mod(dy,P,inv); u64 lam[4]; modmul(thr,inv,P,lam);
        u64 l2[4]; modmul(lam,lam,P,l2); u64 x3[4]; modsub_p(l2,x1,x3); modsub_p(x3,x1,x3);
        u64 t[4]; modsub_p(x1,x3,t); modmul(lam,t,P,t); u64 y3[4]; modsub_p(t,y1,y3);
        cp4(p1,x3); cp4(p1+4,y3); return;
    }
    u64 dx[4]; modsub_p(x2,x1,dx); u64 dy[4]; modsub_p(y2,y1,dy);
    u64 inv[4]; inv_mod(dx,P,inv); u64 lam[4]; modmul(dy,inv,P,lam);
    u64 l2[4]; modmul(lam,lam,P,l2); u64 x3[4]; modsub_p(l2,x1,x3); modsub_p(x3,x2,x3);
    u64 t[4]; modsub_p(x1,x3,t); modmul(lam,t,P,t); u64 y3[4]; modsub_p(t,y1,y3);
    cp4(p1,x3); cp4(p1+4,y3);
}
void ec_dbl(u64 p[8]) { u64 q[8]; cp8(q,p); ec_add(p,q); }

// 1/x mod N (software).
void fn_inv_hint(const u64 x[4], u64 o[4]) { inv_mod(x,N,o); }

// MSB position of x: limb index (0..3) and bit within limb (0..63).
void msb_pos256(const u64 x[4], u64 *limb, u64 *bit) {
    for (int i=3;i>=0;--i) if (x[i]) {
        u64 w=x[i], pos=0;
        if (w>=(1ULL<<32)){w>>=32;pos+=32;} if (w>=(1ULL<<16)){w>>=16;pos+=16;}
        if (w>=(1ULL<<8)){w>>=8;pos+=8;} if (w>=(1ULL<<4)){w>>=4;pos+=4;}
        if (w>=(1ULL<<2)){w>>=2;pos+=2;} if (w>=(1ULL<<1)){pos+=1;}
        *limb=(u64)i; *bit=pos; return;
    }
    *limb=0; *bit=0;
}

// MSB position across four scalars (their bitwise-OR's MSB is the global MSB).
void msb_pos256_4(const u64 a[4], const u64 b[4], const u64 c[4], const u64 d[4],
                  u64 *limb, u64 *bit) {
    u64 o[4] = {a[0]|b[0]|c[0]|d[0], a[1]|b[1]|c[1]|d[1],
                a[2]|b[2]|c[2]|d[2], a[3]|b[3]|c[3]|d[3]};
    msb_pos256(o, limb, bit);
}

// ---- GLV scalar decomposition (software Babai rounding) --------------------
// Lattice short-basis constants (zisklib fcalls_impl/secp256k1/glv.rs), verified
// A1 + B1·λ ≡ 0 and A2 + B2·λ ≡ 0 (mod N), B2 = A1, -B1 = MINUS_B1.
namespace glv_sw {
const u64 A1[2]       = {0xE86C90E49284EB15ULL, 0x3086D221A7D46BCDULL};
const u64 MINUS_B1[2] = {0x6F547FA90ABFE4C3ULL, 0xE4437ED6010E8828ULL};
const u64 A2[3]       = {0x57C1108D9D44CFD8ULL, 0x14CA50F7A8E2F3F6ULL, 0x1ULL};

// 8-limb (512-bit) little-endian unsigned helpers.
inline void u512_mul(const u64* a, int la, const u64* b, int lb, u64 o[8]) {
    for (int i=0;i<8;++i) o[i]=0;
    for (int i=0;i<la;++i) { u64 c=0;
        for (int j=0;j<lb && i+j<8;++j) {
            unsigned __int128 t=(unsigned __int128)a[i]*b[j]+o[i+j]+c; o[i+j]=(u64)t; c=(u64)(t>>64); }
        if (i+lb<8) o[i+lb]+=c; }
}
inline bool u512_ge(const u64 a[8], const u64 b[8]) {
    for (int i=7;i>=0;--i){ if(a[i]>b[i])return true; if(a[i]<b[i])return false; } return true;
}
inline void u512_sub(u64 a[8], const u64 b[8]) {
    unsigned __int128 br=0; for(int i=0;i<8;++i){ unsigned __int128 t=(unsigned __int128)a[i]-b[i]-br; a[i]=(u64)t; br=(t>>64)&1; }
}
inline void u512_add(u64 a[8], const u64 b[8]) {
    unsigned __int128 c=0; for(int i=0;i<8;++i){ unsigned __int128 t=(unsigned __int128)a[i]+b[i]+c; a[i]=(u64)t; c=t>>64; }
}
inline void u512_shl1(u64 a[8]) { u64 c=0; for(int i=0;i<8;++i){ u64 n=a[i]>>63; a[i]=(a[i]<<1)|c; c=n; } }
inline void u512_set(u64 r[8], const u64* a, int la) { for(int i=0;i<8;++i) r[i]= i<la?a[i]:0; }
inline void u512_div(const u64 num[8], const u64 den[8], u64 q[8]) {  // floor(num/den)
    u64 r[8]={0,0,0,0,0,0,0,0}; for(int i=0;i<8;++i)q[i]=0;
    for(int bit=511;bit>=0;--bit){ u512_shl1(r); r[0]|=(num[bit>>6]>>(bit&63))&1ULL;
        if(u512_ge(r,den)){ u512_sub(r,den); q[bit>>6]|=1ULL<<(bit&63); } }
}
// q = round(a·k / N) for a,k ≥ 0 = floor((2·a·k + N) / (2·N)).
inline void round_div_N(const u64* a, int la, const u64 k[4], u64 q[8]) {
    u64 ak[8]; u512_mul(a,la,k,4,ak);
    u64 num[8]; for(int i=0;i<8;++i)num[i]=ak[i]; u512_shl1(num);       // 2·a·k
    u64 nn[8]; u512_set(nn,N,4); u512_add(num,nn);                      // +N
    u64 twoN[8]; u512_set(twoN,N,4); u512_shl1(twoN);                   // 2N
    u512_div(num,twoN,q);
}
// |a-b| with sign (1 if a<b).
inline void signed_sub(const u64 a[8], const u64 b[8], u64 r[8], u64* sign) {
    if (u512_ge(a,b)) { for(int i=0;i<8;++i)r[i]=a[i]; u512_sub(r,b); *sign=0; }
    else              { for(int i=0;i<8;++i)r[i]=b[i]; u512_sub(r,a); *sign=1; }
}
} // namespace glv_sw

// out = [k1(4), k2(4), sigma1, sigma2]; k = (-1)^s1·k1 + (-1)^s2·k2·λ (mod N),
// |k1|,|k2| < 2^128. Mirrors the ZisK glv_decompose fcall (id 4).
inline void glv_decompose_hint(const u64 k[4], u64 out[10]) {
    using namespace glv_sw;
    u64 c1[8], c2[8];
    round_div_N(A1, 2, k, c1);          // c1 = round(B2·k/N),  B2 = A1
    round_div_N(MINUS_B1, 2, k, c2);    // c2 = round(-B1·k/N)
    u64 c1A1[8], c2A2[8], c1MB1[8], c2A1[8];
    u512_mul(c1,8,A1,2,c1A1);
    u512_mul(c2,8,A2,3,c2A2);
    u512_mul(c1,8,MINUS_B1,2,c1MB1);
    u512_mul(c2,8,A1,2,c2A1);
    u64 neg1[8]; for(int i=0;i<8;++i)neg1[i]=c1A1[i]; u512_add(neg1,c2A2);  // c1·A1 + c2·A2
    u64 kk[8]; u512_set(kk,k,4);
    u64 k1[8], k2[8], s1, s2;
    signed_sub(kk,  neg1,  k1, &s1);    // k1 = k - (c1·A1 + c2·A2)
    signed_sub(c1MB1, c2A1, k2, &s2);   // k2 = c1·(-B1) - c2·B2
    for(int i=0;i<4;++i){ out[i]=k1[i]; out[4+i]=k2[i]; }
    out[8]=s1; out[9]=s2;
}

} // namespace

#else  // ===================== ZisK precompiles / fcalls =====================
namespace {

// d = (a*b + c) mod m
inline void arith256_mod(const u64 a[4], const u64 b[4], const u64 c[4],
                         const u64 m[4], u64 d[4]) {
    struct { const u64 *a, *b, *c, *module; u64 *d; } p{a, b, c, m, d};
    asm volatile("csrs 0x802, %0" : : "r"(&p) : "memory");
}
inline void ec_add(u64 p1[8], const u64 p2[8]) {  // p1 += p2 (affine, in place)
    struct { u64 *p1; const u64 *p2; } pp{p1, p2};
    asm volatile("csrs 0x803, %0" : : "r"(&pp) : "memory");
}
inline void ec_dbl(u64 p[8]) {  // p = 2·p (affine, in place)
    asm volatile("csrs 0x804, %0" : : "r"(p) : "memory");
}

// ---- fcalls (free-input hints, verified by the shared helpers below) -------
inline u64 fcall_get() {
    u64 v; asm volatile("csrr %0, 0xFFE" : "=r"(v)); return v;
}
inline void fn_inv_hint(const u64 x[4], u64 o[4]) {     // fcall id 2: 1/x mod N
    asm volatile("csrs 0x8F2, %0" : : "r"(x) : "memory");   // param: x, 4 words
    asm volatile("csrwi 0x8C0, 2" : : : "memory");          // trigger FN_INV
    o[0]=fcall_get(); o[1]=fcall_get(); o[2]=fcall_get(); o[3]=fcall_get();
}
inline void msb_pos256(const u64 x[4], u64 *limb, u64 *bit) {  // fcall id 17
    u64 one = 1;
    asm volatile("csrs 0x8F0, %0" : : "r"(one) : "memory");  // param: n=1 (direct value)
    asm volatile("csrs 0x8F2, %0" : : "r"(x)   : "memory");  // param: x, 4 words
    asm volatile("csrwi 0x8C0, 17" : : : "memory");          // trigger MSB_POS_256
    *limb=fcall_get(); *bit=fcall_get();
}
// MSB position across four scalars (fcall id 17, 4 inputs).
inline void msb_pos256_4(const u64 a[4], const u64 b[4], const u64 c[4], const u64 d[4],
                         u64 *limb, u64 *bit) {
    u64 four = 4;
    asm volatile("csrs 0x8F0, %0" : : "r"(four) : "memory");  // param: n=4 (direct value)
    asm volatile("csrs 0x8F2, %0" : : "r"(a) : "memory");
    asm volatile("csrs 0x8F2, %0" : : "r"(b) : "memory");
    asm volatile("csrs 0x8F2, %0" : : "r"(c) : "memory");
    asm volatile("csrs 0x8F2, %0" : : "r"(d) : "memory");
    asm volatile("csrwi 0x8C0, 17" : : : "memory");          // trigger MSB_POS_256
    *limb=fcall_get(); *bit=fcall_get();
}
// GLV decomposition hint (fcall id 4): out = [k1(4), k2(4), sigma1, sigma2].
inline void glv_decompose_hint(const u64 k[4], u64 out[10]) {
    asm volatile("csrs 0x8F2, %0" : : "r"(k) : "memory");    // param: k, 4 words
    asm volatile("csrwi 0x8C0, 4" : : : "memory");           // trigger GLV_DECOMPOSE
    for (int i = 0; i < 10; ++i) out[i] = fcall_get();
}

} // namespace
#endif

// ===========================================================================
// Shared high-level logic (built on the backend primitives above).
// ===========================================================================
namespace {

inline void mul_fn(const u64 a[4], const u64 b[4], u64 o[4]) { arith256_mod(a,b,ZERO,N,o); }

inline void reduce_fn(const u64 x[4], u64 o[4]) {  // x mod N (x < 2^256)
    if (lt4(x,N)) { cp4(o,x); return; }
    arith256_mod(x,ONE,ZERO,N,o);
}

// 1/x mod N (x != 0): take the hint, then verify x·inv == 1 (mod N).
inline void inv_fn(const u64 x[4], u64 o[4]) {
    fn_inv_hint(x,o);
    u64 chk[4]; mul_fn(x,o,chk);
    if (!eq4(chk,ONE)) zeg_zisk_halt();  // hint was wrong: must never happen
}

// p1 (+) p2 for non-infinity affine points. Returns false if the sum is 𝒪.
inline bool point_add(const u64 p1[8], const u64 p2[8], u64 r[8]) {
    if (!eq4(p1,p2)) { cp8(r,p1); ec_add(r,p2); return true; }   // x differ -> add
    if (eq4(p1+4,p2+4)) { cp8(r,p1); ec_dbl(r); return true; }   // equal -> double
    return false;                                                // p + (-p) = 𝒪
}

// k·P for non-infinity P, k in [0, N-1]. Returns false if result is 𝒪 (k==0).
// Faithful port of zisklib's scalar_mul_secp256k1: the MSB position is taken
// from a hint and the scalar is recomposed bit-by-bit to verify it.
bool scalar_mul(const u64 k[4], const u64 P_in[8], u64 res[8]) {
    if (is_zero4(k)) return false;
    if (eq4(k,ONE)) { cp8(res,P_in); return true; }
    if (eq4(k,TWO)) { cp8(res,P_in); ec_dbl(res); return true; }

    u64 limb, bit; msb_pos256(k,&limb,&bit);
    if (((k[limb]>>bit)&1) != 1) zeg_zisk_halt();   // first hinted bit must be set

    cp8(res,P_in);
    u64 k_rec[4]={0,0,0,0}; k_rec[limb] = 1ULL<<bit;

    int li=(int)limb, curbit;
    if (bit==0) { li-=1; curbit=63; } else curbit=(int)bit-1;

    for (int i=li;i>=0;--i) {
        for (int j=curbit;j>=0;--j) {
            ec_dbl(res);
            if ((k[i]>>j)&1ULL) { ec_add(res,P_in); k_rec[i] |= 1ULL<<j; }
        }
        curbit=63;
    }
    if (!eq4(k_rec,k)) zeg_zisk_halt();             // recomposed scalar must match
    return true;
}

// ===========================================================================
// GLV endomorphism double-scalar multiplication: Q = u1·G + u2·R.
// Faithful port of zisklib glv_double_scalar_mul_with_g_secp256k1: each scalar
// is split into two ~128-bit halves (u1 → a1 + a2·λ over G, φ(G); u2 → b1 + b2·λ
// over R, φ(R)), and all four half-scalars are consumed in a single Strauss-
// Shamir pass over ~128 bits with a 4-bit precomputed base table. This roughly
// halves the doublings and the additions versus two independent 256-bit
// double-and-adds — cutting the secp256k1_add/dbl precompile calls per ecrecover.
// ===========================================================================

// φ(P) = (β·x, y).
inline void phi_pt(const u64 p[8], u64 out[8]) {
    arith256_mod(BETA, p, ZERO, P, out);   // β·x mod P
    cp4(out + 4, p + 4);
}
// -P = (x, P - y).
inline void neg_pt(const u64 p[8], u64 out[8]) {
    cp4(out, p);
    arith256_mod(p + 4, P_MINUS_ONE, ZERO, P, out + 4);   // (P-1)·y = -y mod P
}
inline void neg_fn(const u64 x[4], u64 o[4]) { arith256_mod(x, N_MINUS_ONE, ZERO, N, o); }
inline void add_fn(const u64 x[4], const u64 y[4], u64 o[4]) { arith256_mod(x, ONE, y, N, o); }
inline void sub_fn(const u64 x[4], const u64 y[4], u64 o[4]) { arith256_mod(y, N_MINUS_ONE, x, N, o); }

// In-place p1 += p2 for on-curve non-infinity points; returns true iff the sum
// is 𝒪. Mirrors add_non_infinity_points_secp256k1 (ec_add needs x1≠x2; equal
// points double; p + (-p) = 𝒪).
inline bool add_ni(u64 p1[8], const u64 p2[8]) {
    if (!eq4(p1, p2))     { ec_add(p1, p2); return false; }
    if (eq4(p1+4, p2+4))  { ec_dbl(p1);     return false; }
    return true;
}

// GLV-decompose k ∈ [0,N) into (k1,k2,s1,s2) with |k1|,|k2| < 2^128 and
// k ≡ (-1)^s1·k1 + (-1)^s2·k2·λ (mod N). Hinted then fully verified.
inline void glv_decompose(const u64 k[4], u64 k1[4], u64 k2[4], u64* s1, u64* s2) {
    u64 h[10]; glv_decompose_hint(k, h);
    cp4(k1, h); cp4(k2, h + 4); *s1 = h[8]; *s2 = h[9];
    if (k1[2] || k1[3] || k2[2] || k2[3]) zeg_zisk_halt();   // magnitudes < 2^128
    if (*s1 > 1 || *s2 > 1) zeg_zisk_halt();                 // sign bits
    u64 k1f[4], k2f[4];
    if (*s1) neg_fn(k1, k1f); else cp4(k1f, k1);
    if (*s2) neg_fn(k2, k2f); else cp4(k2f, k2);
    u64 chk[4]; arith256_mod(LAMBDA, k2f, k1f, N, chk);      // λ·k2f + k1f mod N
    if (!eq4(chk, k)) zeg_zisk_halt();                       // relation must hold
}

// Q = u1·G + u2·R (R on-curve, non-infinity, canonical). Returns false if 𝒪.
bool glv_double_scalar_mul_with_g(const u64 u1[4], const u64 u2[4],
                                  const u64 R[8], u64 out[8]) {
    u64 k1[4], k2[4]; reduce_fn(u1, k1); reduce_fn(u2, k2);
    const bool z1 = is_zero4(k1), z2 = is_zero4(k2);
    if (z1 && z2) return false;                              // 𝒪
    if (z1) return scalar_mul(k2, R, out);                  // u2·R
    if (z2) return scalar_mul(k1, G, out);                  // u1·G
    if (eq4(k1, k2)) {                                       // u1·(G+R)
        u64 GR[8]; if (!point_add(G, R, GR)) return false;
        return scalar_mul(k1, GR, out);
    }
    if (eq4(R, GX)) {                                        // R = ±G ⇒ (u1±u2)·G
        u64 kk[4];
        if (eq4(R + 4, G_NEG_Y)) sub_fn(k1, k2, kk); else add_fn(k1, k2, kk);
        return scalar_mul(kk, G, out);
    }

    // GLV-decompose both scalars → four half-scalars.
    u64 a1[4], a2[4], b1[4], b2[4], sa1, sa2, sb1, sb2;
    glv_decompose(k1, a1, a2, &sa1, &sa2);
    glv_decompose(k2, b1, b2, &sb1, &sb2);

    // The four sign-adjusted bases: ±G, ±φ(G), ±R, ±φ(R).
    u64 base_g[8];     cp8(base_g,     sa1 ? G_NEG     : G);
    u64 base_g_phi[8]; cp8(base_g_phi, sa2 ? G_PHI_NEG : G_PHI);
    u64 p_phi[8]; phi_pt(R, p_phi);
    u64 base_p[8];     if (sb1) neg_pt(R,     base_p);     else cp8(base_p,     R);
    u64 base_p_phi[8]; if (sb2) neg_pt(p_phi, base_p_phi); else cp8(base_p_phi, p_phi);
    const u64* bases[4] = {base_g, base_g_phi, base_p, base_p_phi};

    // Precompute the 15 base combinations, indexed by a 4-bit mask
    // (bit0=base_g, bit1=base_g_phi, bit2=base_p, bit3=base_p_phi). T[0] = 𝒪.
    u64 T[16][8]; bool Tinf[16]; Tinf[0] = true;
    for (int m = 1; m < 16; ++m) {
        bool inf = true;
        for (int b = 0; b < 4; ++b) if (m & (1 << b)) {
            if (inf) { cp8(T[m], bases[b]); inf = false; }
            else       inf = add_ni(T[m], bases[b]);
        }
        Tinf[m] = inf;
    }

    // Strauss-Shamir over ~128 bits with bit-by-bit reconstruction of each half.
    u64 limb, bit; msb_pos256_4(a1, a2, b1, b2, &limb, &bit);
    if (limb >= 4 || bit >= 64) zeg_zisk_halt();
    if ((((a1[limb] | a2[limb] | b1[limb] | b2[limb]) >> bit) & 1) != 1) zeg_zisk_halt();

    u64 res[8]; bool res_inf = true;
    u64 a1r[4]={0,0,0,0}, a2r[4]={0,0,0,0}, b1r[4]={0,0,0,0}, b2r[4]={0,0,0,0};
    int start = (int)bit;
    for (int i = (int)limb; i >= 0; --i) {
        const u64 wa1=a1[i], wa2=a2[i], wb1=b1[i], wb2=b2[i];
        u64 ra1=0, ra2=0, rb1=0, rb2=0;
        for (int j = start; j >= 0; --j) {
            if (!res_inf) ec_dbl(res);
            const u64 m = ((wa1>>j)&1) | (((wa2>>j)&1)<<1) | (((wb1>>j)&1)<<2) | (((wb2>>j)&1)<<3);
            if (m) {
                if (!Tinf[m]) {
                    if (res_inf) { cp8(res, T[m]); res_inf = false; }
                    else           res_inf = add_ni(res, T[m]);
                }
                const u64 oj = 1ULL << j;
                if (m & 1) ra1 |= oj;
                if (m & 2) ra2 |= oj;
                if (m & 4) rb1 |= oj;
                if (m & 8) rb2 |= oj;
            }
        }
        a1r[i]=ra1; a2r[i]=ra2; b1r[i]=rb1; b2r[i]=rb2;
        start = 63;
    }
    if (!eq4(a1r,a1) || !eq4(a2r,a2) || !eq4(b1r,b1) || !eq4(b2r,b2)) zeg_zisk_halt();
    if (res_inf) return false;
    cp8(out, res);
    return true;
}

// o = a - b (assumes a >= b; no borrow out). Used for field/scalar negation.
inline void sub4(const u64 a[4], const u64 b[4], u64 o[4]) {
    unsigned __int128 borrow = 0;
    for (int i = 0; i < 4; ++i) {
        unsigned __int128 d = (unsigned __int128)a[i] - b[i] - borrow;
        o[i] = (u64)d;
        borrow = (d >> 64) & 1;
    }
}

// o = base^e mod P, square-and-multiply (LSB first). Uses temporaries so the
// arith256_mod precompile never aliases input and output.
inline void modpow_p(const u64 base[4], const u64 e[4], u64 o[4]) {
    u64 r[4] = {1, 0, 0, 0}, b[4], t[4];
    cp4(b, base);
    for (int i = 0; i < 256; ++i) {
        if ((e[i >> 6] >> (i & 63)) & 1ULL) { arith256_mod(r, b, ZERO, P, t); cp4(r, t); }
        arith256_mod(b, b, ZERO, P, t); cp4(b, t);
    }
    cp4(o, r);
}

// Square-root hint for Fp: sets *is_qr and y such that
//   *is_qr == 1: y² ≡ alpha (mod P), with y's parity == `parity`;
//   *is_qr == 0: y² ≡ alpha·NQR3 (mod P) — a witness that alpha has no root.
// The hint is UNTRUSTED either way; the caller must verify it (see
// secp256k1_ecdsa_recover). ZisK backend: the fp_sqrt fcall (id 3). Software
// backend: the same contract computed locally via modpow_p, so both backends
// exercise identical caller logic.
inline void fp_sqrt_hint(const u64 alpha[4], u64 parity, u64* is_qr, u64 y[4]) {
#if defined(ZEG_SECP256K1_SW)
    u64 cand[4]; modpow_p(alpha, P_PLUS_1_DIV_4, cand);
    u64 sq[4];   arith256_mod(cand, cand, ZERO, P, sq);
    if (eq4(sq, alpha)) {
        *is_qr = 1;
        if ((cand[0] & 1ULL) != parity) { u64 n[4]; sub4(P, cand, n); cp4(cand, n); }
        cp4(y, cand);
    } else {
        *is_qr = 0;
        u64 an[4]; arith256_mod(alpha, NQR3, ZERO, P, an);
        modpow_p(an, P_PLUS_1_DIV_4, y);
    }
#else
    asm volatile("csrs 0x8F2, %0" : : "r"(alpha)  : "memory");  // param: alpha, 4 words
    asm volatile("csrs 0x8F0, %0" : : "r"(parity) : "memory");  // param: parity (direct)
    asm volatile("csrwi 0x8C0, 3" : : : "memory");              // trigger FP_SQRT
    *is_qr = fcall_get();
    y[0]=fcall_get(); y[1]=fcall_get(); y[2]=fcall_get(); y[3]=fcall_get();
#endif
}

} // namespace

// ===========================================================================
// Public ABI: EVM ECRECOVER. Given message hash z, signature (r, s) and the
// recovery id recid (0 or 1 — i.e. EVM v of 27 or 28), recover the signing
// public key into pubkey_out (x[4] || y[4], little-endian limbs). Returns 0 on
// success, non-zero when the signature is not recoverable (caller emits the
// empty ECRECOVER output). Mirrors evmmax::secp256k1::ecrecover semantics.
//
//   R = (r, y) with y ≡ recid (mod 2), y = sqrt(r^3 + 7) mod P
//   Q = r^{-1} (s·R − z·G) = (-z·r^{-1})·G + (s·r^{-1})·R
//
// The scalar multiplications reuse the same accelerated scalar_mul used by
// verify; the only extra field work is the modular square root for R.y.
// ===========================================================================
extern "C" int secp256k1_ecdsa_recover(
        const uint64_t *z, const uint64_t *r, const uint64_t *s,
        unsigned recid, uint64_t *pubkey_out) {
    if (recid > 1) return 1;
    if (is_zero4(r) || !lt4(r, N)) return 1;   // r in [1, N-1]
    if (is_zero4(s) || !lt4(s, N)) return 1;   // s in [1, N-1]

    // R.x = r (r < N < P, so no x = r + N case for recid 0/1).
    // alpha = r^3 + 7 (mod P).
    u64 r2[4], r3[4], alpha[4];
    arith256_mod(r,  r,   ZERO,  P, r2);
    arith256_mod(r2, r,   ZERO,  P, r3);
    arith256_mod(r3, ONE, SEVEN, P, alpha);

    // y = sqrt(alpha) with parity == recid, via the fp_sqrt hint. The hint is
    // untrusted, so verify whichever claim it makes:
    //   root exists  -> y² ≡ alpha (mod P), y canonical (< P, else its parity
    //                   is ill-defined: y and y+P square identically), parity
    //                   == recid;
    //   no root      -> y is a witness with y² ≡ alpha·NQR3 (mod P), which
    //                   proves alpha is a non-residue (NQR3 is a fixed
    //                   non-residue) -> R does not exist, not recoverable.
    // A hint that satisfies neither claim is impossible on a valid run.
    u64 is_qr, y[4];
    fp_sqrt_hint(alpha, recid, &is_qr, y);
    u64 y2[4]; arith256_mod(y, y, ZERO, P, y2);
    if (is_qr) {
        if (!lt4(y, P)) return 1;
        if (!eq4(y2, alpha)) zeg_zisk_halt();            // wrong hint: must never happen
        if ((y[0] & 1ULL) != recid) zeg_zisk_halt();
    } else {
        u64 an[4]; arith256_mod(alpha, NQR3, ZERO, P, an);
        if (!eq4(y2, an)) zeg_zisk_halt();               // witness must prove non-residue
        return 1;                                     // no R exists → not recoverable
    }

    u64 R[8]; cp4(R, r); cp4(R + 4, y);

    // u1 = (-z)·r^{-1} mod N ; u2 = s·r^{-1} mod N.
    u64 zn[4];   reduce_fn(z, zn);
    u64 rinv[4]; inv_fn(r, rinv);
    u64 negz[4]; if (is_zero4(zn)) cp4(negz, zn); else sub4(N, zn, negz);
    u64 u1[4]; mul_fn(negz, rinv, u1);
    u64 u2[4]; mul_fn(s,    rinv, u2);

    // Q = u1·G + u2·R, via the GLV endomorphism (Strauss-Shamir over four
    // ~128-bit half-scalars) — the same result as two 256-bit scalar muls plus a
    // point add, at roughly half the secp256k1_add/dbl precompile calls.
    u64 Q[8];
    if (!glv_double_scalar_mul_with_g(u1, u2, R, Q)) return 1;  // 𝒪 → not recoverable

    cp8(pubkey_out, Q);
    return 0;
}

#endif  // ZEG_ZISK
