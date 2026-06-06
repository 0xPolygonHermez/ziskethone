# BLS12-381 + KZG port (for the EIP-4844 point-eval precompile)

Self-contained C++ port of ziskos's `zisklib/lib/bls12_381`, to implement
`evmone::crypto::kzg_verify_proof` on ZisK. Dual backend selected by `ZEG_ZISK`
(precompiles + fcall hints) vs software (host unit tests). Built layer by layer;
each layer verified before the next. See the plan in `~/.claude/plans/`.

## Backend encoding (authoritative, from ziskos)

- **arith384_mod** (Fp `d=(a*b+c) mod m`): `csrs 0x80B, &params`, params =
  `{const u64* a,b,c,module; u64* d;}` each →`[u64;6]`.
- **G1 curve add/dbl**: `csrs 0x80C / 0x80D`. **Fp2 complex add/sub/mul**:
  `csrs 0x80E / 0x80F / 0x810`. (structs: point = x[6]||y[6]; complex = re[6]||im[6])
- **fcall** (unverified hint; caller MUST verify):
  - param push: `csrs (0x8F0 + words_to_port(bucket)), ptr`. bucket = next
    supported ≥ N from {1→0,2→1,4→2,8→3,12→4,16→5,20→6,24→7,28→8,32→9,48→10,…}.
    e.g. Fp(6)→bucket 8→`0x8F3`; Fp2(12)→bucket 12→`0x8F4`; G2(24)→`0x8F7`.
    The emulator copies `bucket` words, so pad the source buffer to `bucket`.
  - trigger: `csrwi (0x8C0 + (id>>5)), (id & 0x1f)`  (ids <32 → `csrwi 0x8C0, id`).
  - read results: `csrr 0xFFE` per u64.
  - fcall ids: fp_inv 10, fp_sqrt 11, fp2_inv 12, fp2_sqrt 13,
    twist_add_line_coeffs 14, twist_dbl_line_coeffs 15.

## Layers / status

1. **Fp** — done (`fp.hpp`, `test/test_fp.cpp`; KAT vs zisklib Rust tests). ✅
2. **Fp2** — done (`fp2.hpp`, `test/test_fp2.cpp`; KAT vs zisklib Rust tests). ✅
3. **Fp6 / Fp12** — done (`fp6.hpp`, `fp12.hpp`, `test/test_fp12.cpp`; algebraic
   identities incl. Frobenius order-12/multiplicativity, sparse==full). ✅
   (cyclotomic squaring/exp deferred to Layer 6 final-exp, where it's used.)
4. **G1** — done (`g1.hpp`, `test/test_g1.cpp`; decompress(gen), on-curve,
   GLV subgroup, r·G==O). ✅
5. **G2 twist** — done (`g2.hpp`, `test/test_g2.cpp`; on-curve, r·G==O). Affine
   over Fp2, no precompile. KZG needs only add/dbl/neg/scalar-mul over constants;
   Miller-loop line-coeff fcalls (14/15) live in Layer 6. ✅
6. Miller loop + final exp + pairing — todo
7. kzg_verify_proof glue + constants — todo
8. integrate (replace stub, CMake) + end-to-end block 25231946 — todo

## Host tests

`c++ -std=c++20 -O2 -I.. test/test_<layer>.cpp -o /tmp/t && /tmp/t`
(software backend; later layers may also KAT against blst from
`cpp-guest/build/_deps/evmone-build/deps/src/blst`).

Reference: `../../../../zisk/ziskos/entrypoint/src/zisklib/lib/bls12_381/`.
