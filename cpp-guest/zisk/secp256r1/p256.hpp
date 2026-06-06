// p256.hpp — secp256r1 / P-256 ECDSA verification for the ZisK guest (EIP-7951).
//
// Self-contained dual-backend port of ziskos's zisklib secp256r1, mirroring
// secp256k1.cpp. Selected by ZEG_ZISK:
//   ZEG_ZISK : field/scalar mul via arith256_mod (CSR 0x802); curve add/dbl via
//              the secp256r1 precompiles (0x817/0x818); 1/x mod n via the
//              secp256r1 fn_inv fcall (id 5); MSB position via msb_pos_256 (id 17).
//              All hints verified in-circuit.
//   else     : portable software (256-bit mul+reduce, Fermat inverse) for host
//              tests against evmone's secp256r1.
//
// Limbs are little-endian uint64_t[4]; points are uint64_t[8] = x[4]||y[4].
// Faithful to zisklib/lib/secp256r1/{ecdsa,curve,field,scalar}.rs.

#pragma once

#include <cstdint>

namespace zeg::r1 {

typedef uint64_t u64;

// ---- P-256 constants (little-endian limbs), from zisklib constants.rs --------
inline constexpr u64 P[4]   = {0xFFFFFFFFFFFFFFFFULL, 0x00000000FFFFFFFFULL, 0x0000000000000000ULL, 0xFFFFFFFF00000001ULL};
inline constexpr u64 N[4]   = {0xF3B9CAC2FC632551ULL, 0xBCE6FAADA7179E84ULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFF00000000ULL};
inline constexpr u64 E_A[4] = {0xFFFFFFFFFFFFFFFCULL, 0x00000000FFFFFFFFULL, 0x0000000000000000ULL, 0xFFFFFFFF00000001ULL};  // a = -3
inline constexpr u64 E_B[4] = {0x3BCE3C3E27D2604BULL, 0x651D06B0CC53B0F6ULL, 0xB3EBBD55769886BCULL, 0x5AC635D8AA3A93E7ULL};
inline constexpr u64 GX[4]  = {0xF4A13945D898C296ULL, 0x77037D812DEB33A0ULL, 0xF8BCE6E563A440F2ULL, 0x6B17D1F2E12C4247ULL};
inline constexpr u64 GY[4]  = {0xCBB6406837BF51F5ULL, 0x2BCE33576B315ECEULL, 0x8EE7EB4A7C0F9E16ULL, 0x4FE342E2FE1A7F9BULL};
inline constexpr u64 G[8]   = {GX[0],GX[1],GX[2],GX[3], GY[0],GY[1],GY[2],GY[3]};
inline constexpr u64 ZERO[4]= {0,0,0,0};
inline constexpr u64 ONE[4] = {1,0,0,0};

inline void cp4(u64 d[4], const u64 s[4]) { d[0]=s[0]; d[1]=s[1]; d[2]=s[2]; d[3]=s[3]; }
inline void cp8(u64 d[8], const u64 s[8]) { for (int i=0;i<8;++i) d[i]=s[i]; }
inline bool eq4(const u64 a[4], const u64 b[4]) { return a[0]==b[0]&&a[1]==b[1]&&a[2]==b[2]&&a[3]==b[3]; }
inline bool eq8(const u64 a[8], const u64 b[8]) { for(int i=0;i<8;++i) if(a[i]!=b[i]) return false; return true; }
inline bool is_zero4(const u64 a[4]) { return a[0]==0&&a[1]==0&&a[2]==0&&a[3]==0; }
inline bool lt4(const u64 a[4], const u64 b[4]) {  // a < b
    for (int i=3;i>=0;--i) { if (a[i]<b[i]) return true; if (a[i]>b[i]) return false; }
    return false;
}

// ===========================================================================
// Backend: arith256_mod, ec_add (0x817), ec_dbl (0x818), fn_inv, msb_pos256.
// ===========================================================================
#if defined(ZEG_ZISK)

inline void arith256_mod(const u64 a[4], const u64 b[4], const u64 c[4], const u64 m[4], u64 d[4]) {
    struct { const u64 *a, *b, *c, *module; u64 *d; } p{a, b, c, m, d};
    asm volatile("csrs 0x802, %0" : : "r"(&p) : "memory");
}
inline void ec_add(u64 p1[8], const u64 p2[8]) {  // p1 += p2 (affine, in place)
    struct { u64 *p1; const u64 *p2; } pp{p1, p2};
    asm volatile("csrs 0x817, %0" : : "r"(&pp) : "memory");
}
inline void ec_dbl(u64 p[8]) {  // p = 2·p (affine, in place)
    asm volatile("csrs 0x818, %0" : : "r"(p) : "memory");
}
inline u64 fcall_get() { u64 v; asm volatile("csrr %0, 0xFFE" : "=r"(v)); return v; }
inline void fn_inv_hint(const u64 x[4], u64 o[4]) {     // fcall id 5: 1/x mod n
    asm volatile("csrs 0x8F2, %0" : : "r"(x) : "memory");
    asm volatile("csrwi 0x8C0, 5" : : : "memory");       // FCALL_SECP256R1_FN_INV_ID
    o[0]=fcall_get(); o[1]=fcall_get(); o[2]=fcall_get(); o[3]=fcall_get();
}
inline void msb_pos256(const u64 x[4], u64 *limb, u64 *bit) {  // fcall id 17
    u64 one = 1;
    asm volatile("csrs 0x8F0, %0" : : "r"(one) : "memory");
    asm volatile("csrs 0x8F2, %0" : : "r"(x)   : "memory");
    asm volatile("csrwi 0x8C0, 17" : : : "memory");
    *limb=fcall_get(); *bit=fcall_get();
}

#else  // ===================== portable software (host) =====================

namespace detail {
inline void mul256(const u64 a[4], const u64 b[4], u64 out[8]) {
    for (int i=0;i<8;++i) out[i]=0;
    for (int i=0;i<4;++i) { u64 carry=0;
        for (int j=0;j<4;++j) { unsigned __int128 t=(unsigned __int128)a[i]*b[j]+out[i+j]+carry; out[i+j]=(u64)t; carry=(u64)(t>>64); }
        out[i+4]+=carry; }
}
inline bool ge_512_256(const u64 r[8], const u64 m[4]) {
    for (int i=7;i>=4;--i) if (r[i]) return true;
    for (int i=3;i>=0;--i) { if (r[i]>m[i]) return true; if (r[i]<m[i]) return false; }
    return true;
}
inline void sub_m_512(u64 r[8], const u64 m[4]) {
    unsigned __int128 borrow=0;
    for (int i=0;i<8;++i) { u64 mi=(i<4)?m[i]:0; unsigned __int128 t=(unsigned __int128)r[i]-mi-borrow; r[i]=(u64)t; borrow=(t>>64)&1; }
}
inline void mod512(const u64 num[8], const u64 m[4], u64 out[4]) {
    u64 r[8]={0,0,0,0,0,0,0,0};
    for (int i=511;i>=0;--i) {
        u64 carry=0; for (int k=0;k<8;++k){ u64 nx=(r[k]>>63)&1; r[k]=(r[k]<<1)|carry; carry=nx; }
        r[0] |= (num[i>>6]>>(i&63)) & 1ULL;
        if (ge_512_256(r,m)) sub_m_512(r,m);
    }
    for (int i=0;i<4;++i) out[i]=r[i];
}
}  // namespace detail

inline void arith256_mod(const u64 a[4], const u64 b[4], const u64 c[4], const u64 m[4], u64 d[4]) {
    u64 t[8]; detail::mul256(a,b,t);
    unsigned __int128 carry=0;
    for (int i=0;i<8;++i){ u64 ci=(i<4)?c[i]:0; unsigned __int128 s=(unsigned __int128)t[i]+ci+carry; t[i]=(u64)s; carry=s>>64; }
    detail::mod512(t,m,d);
}
namespace detail {
inline void modmul(const u64 a[4], const u64 b[4], const u64 m[4], u64 o[4]) { arith256_mod(a,b,ZERO,m,o); }
inline void modsub(const u64 a[4], const u64 b[4], const u64 m[4], u64 o[4]) {  // (a-b) mod m
    u64 negb[4]; unsigned __int128 borrow=0;
    for (int i=0;i<4;++i){ unsigned __int128 t=(unsigned __int128)m[i]-b[i]-borrow; negb[i]=(u64)t; borrow=(t>>64)&1; }
    arith256_mod(a,ONE,negb,m,o);
}
inline void modpow(const u64 base[4], const u64 e[4], const u64 m[4], u64 o[4]) {
    u64 res[4]; cp4(res,ONE);
    for (int i=255;i>=0;--i){ u64 t[4]; modmul(res,res,m,t); cp4(res,t);
        if ((e[i>>6]>>(i&63))&1ULL){ modmul(res,base,m,t); cp4(res,t); } }
    cp4(o,res);
}
}  // namespace detail
inline void fn_inv_hint(const u64 x[4], u64 o[4]) { u64 e[4]; cp4(e,N); e[0]-=2; detail::modpow(x,e,N,o); }  // x^(n-2) mod n
inline void msb_pos256(const u64 x[4], u64 *limb, u64 *bit) {
    for (int i=3;i>=0;--i) if (x[i]) {
        u64 w=x[i], pos=0;
        if (w>=(1ULL<<32)){w>>=32;pos+=32;} if (w>=(1ULL<<16)){w>>=16;pos+=16;}
        if (w>=(1ULL<<8)){w>>=8;pos+=8;} if (w>=(1ULL<<4)){w>>=4;pos+=4;}
        if (w>=(1ULL<<2)){w>>=2;pos+=2;} if (w>=(1ULL<<1)){pos+=1;}
        *limb=(u64)i; *bit=pos; return;
    }
    *limb=0; *bit=0;
}
// software EC affine add/dbl (host only), curve a=-3, prime P.
inline void ec_add(u64 p1[8], const u64 p2[8]) {
    const u64 *x1=p1,*y1=p1+4,*x2=p2,*y2=p2+4;
    if (eq4(x1,x2)) {
        if (!eq4(y1,y2)) { for(int i=0;i<8;++i) p1[i]=0; return; }
        u64 xx[4]; detail::modmul(x1,x1,P,xx);
        const u64 THREE[4]={3,0,0,0}; u64 thr[4]; detail::modmul(xx,THREE,P,thr);
        u64 num[4]; detail::modsub(thr, THREE, P, num);  // 3x² + a = 3x² - 3 (a = -3)
        const u64 TWO[4]={2,0,0,0}; u64 dy[4]; arith256_mod(y1,TWO,ZERO,P,dy);
        u64 inv[4]; { u64 e[4]; cp4(e,P); e[0]-=2; detail::modpow(dy,e,P,inv); }
        u64 lam[4]; detail::modmul(num,inv,P,lam);
        u64 l2[4]; detail::modmul(lam,lam,P,l2); u64 x3[4]; detail::modsub(l2,x1,P,x3); detail::modsub(x3,x1,P,x3);
        u64 t[4]; detail::modsub(x1,x3,P,t); detail::modmul(lam,t,P,t); u64 y3[4]; detail::modsub(t,y1,P,y3);
        cp4(p1,x3); cp4(p1+4,y3); return;
    }
    u64 dx[4]; detail::modsub(x2,x1,P,dx); u64 dy[4]; detail::modsub(y2,y1,P,dy);
    u64 inv[4]; { u64 e[4]; cp4(e,P); e[0]-=2; detail::modpow(dx,e,P,inv); }
    u64 lam[4]; detail::modmul(dy,inv,P,lam);
    u64 l2[4]; detail::modmul(lam,lam,P,l2); u64 x3[4]; detail::modsub(l2,x1,P,x3); detail::modsub(x3,x2,P,x3);
    u64 t[4]; detail::modsub(x1,x3,P,t); detail::modmul(lam,t,P,t); u64 y3[4]; detail::modsub(t,y1,P,y3);
    cp4(p1,x3); cp4(p1+4,y3);
}
inline void ec_dbl(u64 p[8]) { u64 q[8]; cp8(q,p); ec_add(p,q); }

#endif  // backend

// ===========================================================================
// Shared high-level logic.
// ===========================================================================
inline void fp_mul(const u64 a[4], const u64 b[4], u64 o[4]) { arith256_mod(a,b,ZERO,P,o); }
inline void fp_add(const u64 a[4], const u64 b[4], u64 o[4]) { arith256_mod(a,ONE,b,P,o); }
inline void fn_mul(const u64 a[4], const u64 b[4], u64 o[4]) { arith256_mod(a,b,ZERO,N,o); }
inline void reduce_fn(const u64 x[4], u64 o[4]) { if (lt4(x,N)) cp4(o,x); else arith256_mod(x,ONE,ZERO,N,o); }

// 1/x mod n (x != 0): hint then verify x·inv == 1 (mod n).
inline void inv_fn(const u64 x[4], u64 o[4]) {
    fn_inv_hint(x,o);
    u64 chk[4]; fn_mul(x,o,chk);
    if (!eq4(chk,ONE)) { for(;;){} }
}

// y² == x³ + a·x + b  (a = -3); pk = x[4]||y[4].
inline bool is_on_curve(const u64 pk[8]) {
    const u64 *x=pk, *y=pk+4;
    u64 lhs[4]; fp_mul(y,y,lhs);
    u64 x2[4]; fp_mul(x,x,x2); u64 x3[4]; fp_mul(x2,x,x3);
    u64 ax[4]; fp_mul(E_A,x,ax);
    u64 rhs[4]; fp_add(x3,ax,rhs); fp_add(rhs,E_B,rhs);
    return eq4(lhs,rhs);
}

// p1 (+) p2 for non-∞ affine points. Returns false if the sum is 𝒪.
inline bool point_add(const u64 p1[8], const u64 p2[8], u64 r[8]) {
    if (!eq4(p1,p2)) { cp8(r,p1); ec_add(r,p2); return true; }
    if (eq4(p1+4,p2+4)) { cp8(r,p1); ec_dbl(r); return true; }
    return false;
}

// k·P for non-∞ P, k in [0, n-1]. Returns false if result is 𝒪 (k==0).
inline bool scalar_mul(const u64 k[4], const u64 P_in[8], u64 res[8]) {
    if (is_zero4(k)) return false;
    if (eq4(k,ONE)) { cp8(res,P_in); return true; }
    const u64 TWO[4]={2,0,0,0};
    if (eq4(k,TWO)) { cp8(res,P_in); ec_dbl(res); return true; }
    u64 limb, bit; msb_pos256(k,&limb,&bit);
    if (((k[limb]>>bit)&1) != 1) { for(;;){} }
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
    if (!eq4(k_rec,k)) { for(;;){} }
    return true;
}

// Full EIP-7951 ECDSA verify. pk = x[4]||y[4], z/r/s = 4-limb LE. Returns valid.
inline bool ecdsa_verify(const u64 pk[8], const u64 z[4], const u64 r[4], const u64 s[4]) {
    // r, s ∈ [1, n-1]
    if (is_zero4(r) || !lt4(r,N)) return false;
    if (is_zero4(s) || !lt4(s,N)) return false;
    // pk ≠ 𝒪, coords < p
    if (is_zero4(pk) && is_zero4(pk+4)) return false;
    if (!lt4(pk,P) || !lt4(pk+4,P)) return false;
    if (!is_on_curve(pk)) return false;

    u64 sinv[4]; inv_fn(s, sinv);
    u64 u1[4]; fn_mul(z, sinv, u1);
    u64 u2[4]; fn_mul(r, sinv, u2);

    u64 A[8], B[8], R[8];
    bool hasA = scalar_mul(u1, G,  A);
    bool hasB = scalar_mul(u2, pk, B);
    bool hasR;
    if (hasA && hasB)      hasR = point_add(A, B, R);
    else if (hasA)       { cp8(R, A); hasR = true; }
    else if (hasB)       { cp8(R, B); hasR = true; }
    else                   return false;          // u1·G + u2·Q = 𝒪
    if (!hasR) return false;

    // r ≡ R.x (mod n)
    if (eq4(R, r)) return true;
    u64 xr[4]; reduce_fn(R, xr);
    return eq4(xr, r);
}

} // namespace zeg::r1
