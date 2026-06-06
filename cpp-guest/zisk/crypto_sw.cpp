// crypto_sw.cpp — portable software secp256k1 for the ZisK self-contained
// build. Provides the guest's one external crypto symbol:
//
//   int secp256k1_ecdsa_verify(pk, z, r, s, result)
//       result <- (u1·G + u2·PK).(x,y),  u1 = z·s⁻¹ mod n, u2 = r·s⁻¹ mod n
//
// The caller (zeg::verify_and_recover_sender / verify_signature_and_get_signer)
// then checks result.x mod n == r. This mirrors the ZisK lib-c ABI documented in
// include/zeg/zisk_crypto.hpp; the EC math is a direct port of the portable
// (software) path in ../../hello-zisk-c/src/secp256k1.cpp.
//
// Limb convention everywhere: uint64_t[4] little-endian (limb[0] = low 64 bits);
// points are uint64_t[8] = x[4] || y[4]. This is exactly the format the guest
// passes in/expects back, so no endianness conversion is needed here.
//
// NOTE: this is the un-accelerated baseline for benchmarking. The proving build
// will swap this object for the ZisK secp256k1 accelerator.

#include <cstdint>

namespace {

typedef uint64_t u64;

// ---- curve constants (little-endian limbs) --------------------------------
const u64 P[4]  = {0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL,
                   0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL};
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

// ---- EC point ops (affine) -------------------------------------------------
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

inline void reduce_fn(const u64 x[4], u64 o[4]) {  // x mod N
    if (lt4(x,N)) { cp4(o,x); return; }
    arith256_mod(x,ONE,ZERO,N,o);
}
inline void mul_fn(const u64 a[4], const u64 b[4], u64 o[4]) { arith256_mod(a,b,ZERO,N,o); }
inline void inv_fn(const u64 x[4], u64 o[4]) { inv_mod(x,N,o); }  // 1/x mod N

// k·P, k in [1,N-1], P not infinity. Result in res. Returns false if O (k==0).
bool scalar_mul(const u64 k[4], const u64 P_in[8], u64 res[8]) {
    if (is_zero4(k)) return false;
    if (eq4(k,ONE)) { cp8(res,P_in); return true; }
    cp8(res, P_in);
    // double-and-add over the bits below the top set bit
    int top = -1;
    for (int i=3;i>=0 && top<0;--i) if (k[i]) {
        for (int b=63;b>=0;--b) if ((k[i]>>b)&1ULL) { top = i*64+b; break; }
    }
    for (int pos=top-1; pos>=0; --pos) {
        ec_dbl(res);
        if ((k[pos>>6]>>(pos&63))&1ULL) ec_add(res, P_in);
    }
    return true;
}
// p1 (+) p2 for affine points, result in r. false if r == O.
bool point_add(const u64 p1[8], const u64 p2[8], u64 r[8]) {
    if (!eq4(p1,p2)) { cp8(r,p1); ec_add(r,p2); return !(is_zero4(r)&&is_zero4(r+4)); }
    if (eq4(p1+4,p2+4)) { cp8(r,p1); ec_dbl(r); return true; }
    return false;  // p + (-p) = O
}

} // namespace

// ===========================================================================
// Public ABI: compute result = u1·G + u2·PK. Always returns 0 (caller checks
// result.x mod n == r). On a degenerate result (point at infinity) we leave
// result = 0 so the caller's equality check fails and it fatals.
// ===========================================================================
extern "C" int secp256k1_ecdsa_verify(
        const uint64_t *pk, const uint64_t *z, const uint64_t *r,
        const uint64_t *s, uint64_t *result) {
    u64 zn[4]; reduce_fn(z, zn);
    u64 sinv[4]; inv_fn(s, sinv);
    u64 u1[4]; mul_fn(zn, sinv, u1);
    u64 u2[4]; mul_fn(r,  sinv, u2);

    u64 A[8], B[8], R[8];
    bool hasA = scalar_mul(u1, G,  A);
    bool hasB = scalar_mul(u2, pk, B);
    bool hasR;
    if (hasA && hasB)      hasR = point_add(A, B, R);
    else if (hasA)       { cp8(R, A); hasR = true; }
    else if (hasB)       { cp8(R, B); hasR = true; }
    else                   hasR = false;

    if (!hasR) { for (int i=0;i<8;++i) result[i] = 0; return 0; }
    cp8(result, R);
    return 0;
}
