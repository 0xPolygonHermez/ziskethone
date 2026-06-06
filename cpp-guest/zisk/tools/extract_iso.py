#!/usr/bin/env python3
# Extract BLS12-381 map-to-curve constants from zisklib constants.rs → C++ header.
import re, sys

SRC = "/Users/jbaylina/git/zisk/zisk/ziskos/entrypoint/src/zisklib/lib/bls12_381/constants.rs"
txt = open(SRC).read()

# Pull every `pub const NAME: TYPE = <body>;`
consts = {}
for m in re.finditer(r'pub const (\w+)\s*:\s*([^=]+?)=\s*(.*?);', txt, re.S):
    name, typ, body = m.group(1), m.group(2).strip(), m.group(3)
    nums = [int(x.replace('_',''), 16) if x.lower().startswith('0x') else int(x.replace('_',''))
            for x in re.findall(r'0x[0-9A-Fa-f_]+|\b\d+\b', body)]
    consts[name] = (typ, nums)

def fp(limbs):  # 6 u64 → {{...}}
    assert len(limbs) == 6, limbs
    return "{{" + ", ".join("0x%016XULL" % v for v in limbs) + "}}"

def fp2(limbs): # 12 u64 → {c0, c1}
    assert len(limbs) == 12, limbs
    return "{" + fp(limbs[0:6]) + ", " + fp(limbs[6:12]) + "}"

# SWU_Z_G2 is symbolic (P[i]-k); compute from P.
P = consts["P"][1]
consts["SWU_Z_G2"] = ("[u64;12]", [P[0]-2, P[1], P[2], P[3], P[4], P[5],
                                   P[0]-1, P[1], P[2], P[3], P[4], P[5]])

WANT_FP   = ["ISO_A_G1", "ISO_B_G1", "SWU_Z_G1", "SWU_Z2_G1"]
WANT_FP_A = ["ISO_X_NUM_G1", "ISO_X_DEN_G1", "ISO_Y_NUM_G1", "ISO_Y_DEN_G1"]
WANT_FP2  = ["ISO_A_G2", "ISO_B_G2", "SWU_Z_G2"]
WANT_FP2_A= ["ISO_X_NUM_G2", "ISO_X_DEN_G2", "ISO_Y_NUM_G2", "ISO_Y_DEN_G2"]

out = []
out.append("// map_constants.hpp — BLS12-381 SWU + isogeny constants (EIP-2537 map-to-curve).")
out.append("// AUTO-GENERATED from zisklib constants.rs by tools/extract_iso.py — do not edit by hand.")
out.append("// G1: 11-isogeny; G2: 3-isogeny. Fp = 6 u64 LE; Fp2 = {c0,c1}.")
out.append("#pragma once")
out.append('#include "fp.hpp"')
out.append('#include "fp2.hpp"')
out.append("namespace zeg::bls {")

for n in WANT_FP:
    out.append("inline constexpr Fp %s = %s;" % (n, fp(consts[n][1])))
for n in WANT_FP_A:
    limbs = consts[n][1]; cnt = len(limbs)//6
    rows = ",\n  ".join(fp(limbs[i*6:(i+1)*6]) for i in range(cnt))
    out.append("inline constexpr Fp %s[%d] = {\n  %s\n};" % (n, cnt, rows))
for n in WANT_FP2:
    out.append("inline constexpr Fp2 %s = %s;" % (n, fp2(consts[n][1])))
for n in WANT_FP2_A:
    limbs = consts[n][1]; cnt = len(limbs)//12
    rows = ",\n  ".join(fp2(limbs[i*12:(i+1)*12]) for i in range(cnt))
    out.append("inline constexpr Fp2 %s[%d] = {\n  %s\n};" % (n, cnt, rows))

# scalars
out.append("// cofactor h for G1 (single 64-bit limb) and |x| for G2 abs-x mul")
out.append("inline constexpr uint64_t COFACTOR_G1[4] = {0x%016XULL, 0, 0, 0};" % consts["COFACTOR_G1"][1][0])
out.append("} // namespace zeg::bls")
open(sys.argv[1] if len(sys.argv)>1 else "/dev/stdout","w").write("\n".join(out)+"\n")
print("wrote %d FP, %d FP2 arrays" % (len(WANT_FP_A), len(WANT_FP2_A)), file=sys.stderr)
