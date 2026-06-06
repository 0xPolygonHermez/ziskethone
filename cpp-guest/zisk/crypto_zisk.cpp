// crypto_zisk.cpp — ZisK-accelerated secp256k1 for the self-contained guest.
//
// Drop-in replacement for crypto_sw.cpp: same external symbol and ABI
//
//   int secp256k1_ecdsa_verify(pk, z, r, s, result)
//       result <- (u1·G + u2·PK).(x,y),  u1 = z·s⁻¹ mod n, u2 = r·s⁻¹ mod n
//
// but the field/scalar arithmetic and EC point ops are delegated to the ZisK
// precompiles, and the scalar-field inverse + scalar-mul bit length come from
// free-input (fcall) hints that are verified in-circuit — exactly as ziskos's
// `zisklib` does. This is a faithful port of the precompile/fcall branch of
// ../../hello-zisk-c/src/secp256k1.cpp (crypto_sw.cpp was ported from that same
// file's software branch).
//
// The caller (zeg::verify_and_recover_sender / verify_signature_and_get_signer)
// still does the final `result.x mod n == r` ECDSA check; on a degenerate (∞)
// result we leave result = 0 so that check fails closed.
//
// CSRs used (see zisk definitions/src/syscall.rs and hello-zisk-c §8.7):
//   0x802 arith256_mod  d = (a*b + c) mod m   {a,b,c,module,d}
//   0x803 secp256k1_add p1 += p2 (affine)     {p1,p2}
//   0x804 secp256k1_dbl p  = 2·p (affine)     p
//   fcall: 0x8F0/0x8F2 push params, csrwi 0x8C0,<id> trigger, csrr 0xFFE read.
// The emulator (and prover) compute the precompiles and fcalls; nothing here
// links ziskos.
//
// Limb convention everywhere: uint64_t[4] little-endian (limb[0] = low 64 bits);
// points are uint64_t[8] = x[4] || y[4]. Matches the format the guest passes in
// and expects back, so no endianness conversion is needed.

#include <cstdint>

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

// ---- ZisK precompiles -----------------------------------------------------
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

// ---- ZisK fcalls (free-input hints, verified below) -----------------------
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

// ---- scalar (mod N) helpers, built on arith256_mod ------------------------
inline void mul_fn(const u64 a[4], const u64 b[4], u64 o[4]) { arith256_mod(a,b,ZERO,N,o); }

inline void reduce_fn(const u64 x[4], u64 o[4]) {  // x mod N (x < 2^256)
    if (lt4(x,N)) { cp4(o,x); return; }
    arith256_mod(x,ONE,ZERO,N,o);
}

// 1/x mod N (x != 0): hint the inverse, then verify x·inv == 1 (mod N).
inline void inv_fn(const u64 x[4], u64 o[4]) {
    fn_inv_hint(x,o);
    u64 chk[4]; mul_fn(x,o,chk);
    if (!eq4(chk,ONE)) { for(;;){} }  // hint was wrong: must never happen
}

// ---- EC ops on affine points ----------------------------------------------
// p1 (+) p2 for non-infinity points. Returns false if the sum is 𝒪.
inline bool point_add(const u64 p1[8], const u64 p2[8], u64 r[8]) {
    if (!eq4(p1,p2)) { cp8(r,p1); ec_add(r,p2); return true; }   // x differ -> add
    if (eq4(p1+4,p2+4)) { cp8(r,p1); ec_dbl(r); return true; }   // equal -> double
    return false;                                                // p + (-p) = 𝒪
}

// k·P for non-infinity P, k in [0, N-1]. Returns false if result is 𝒪 (k==0).
// Faithful port of zisklib's scalar_mul_secp256k1: the MSB position is hinted
// and the scalar is recomposed bit-by-bit to verify the hint.
bool scalar_mul(const u64 k[4], const u64 P_in[8], u64 res[8]) {
    if (is_zero4(k)) return false;
    if (eq4(k,ONE)) { cp8(res,P_in); return true; }
    if (eq4(k,TWO)) { cp8(res,P_in); ec_dbl(res); return true; }

    u64 limb, bit; msb_pos256(k,&limb,&bit);
    if (((k[limb]>>bit)&1) != 1) { for(;;){} }   // first hinted bit must be set

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
    if (!eq4(k_rec,k)) { for(;;){} }             // recomposed scalar must match
    return true;
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
