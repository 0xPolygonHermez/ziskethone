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

    // Q = u1·G + u2·R.
    u64 A[8], B[8], Q[8];
    bool hasA = scalar_mul(u1, G, A);
    bool hasB = scalar_mul(u2, R, B);
    bool hasQ;
    if (hasA && hasB)      hasQ = point_add(A, B, Q);
    else if (hasA)       { cp8(Q, A); hasQ = true; }
    else if (hasB)       { cp8(Q, B); hasQ = true; }
    else                   hasQ = false;
    if (!hasQ) return 1;   // point at infinity → not recoverable

    cp8(pubkey_out, Q);
    return 0;
}

#endif  // ZEG_ZISK
