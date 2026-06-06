#!/usr/bin/env python3
# Extract BN254 curve + Frobenius constants from zisklib bn254/constants.rs → C++ header.
import re, sys

SRC = "/Users/jbaylina/git/zisk/zisk/ziskos/entrypoint/src/zisklib/lib/bn254/constants.rs"
txt = open(SRC).read()

consts = {}
for m in re.finditer(r'pub const (\w+)\s*:\s*\[u64;\s*(\d+)\]\s*=\s*(.*?);', txt, re.S):
    name, n, body = m.group(1), int(m.group(2)), m.group(3)
    nums = []
    for x in re.findall(r'0x[0-9A-Fa-f_]+|P\[\d\]\s*-\s*\d+|\b\d+\b', body):
        if x.lower().startswith('0x'):
            nums.append(int(x.replace('_', ''), 16))
        elif x.startswith('P['):
            # P[i] - k
            i = int(x[2]); k = int(x.split('-')[1])
            nums.append(consts['P'][i] - k)
        else:
            nums.append(int(x))
    consts[name] = nums

def fp(v):
    assert len(v) == 4, v
    return "{{" + ", ".join("0x%016XULL" % x for x in v) + "}}"

def fp2(v):
    assert len(v) == 8, v
    return "{" + fp(v[0:4]) + ", " + fp(v[4:8]) + "}"

out = []
out.append("// constants.hpp — BN254 curve + Frobenius constants (alt_bn128 precompiles).")
out.append("// AUTO-GENERATED from zisklib bn254/constants.rs by tools/extract_bn254.py.")
out.append("// Fp = 4 u64 LE; Fp2 = {c0,c1} (c0=real, c1=imag·u).")
out.append("#pragma once")
out.append('#include "fp.hpp"')
out.append('#include "fp2.hpp"')
out.append("namespace zeg::bn {")
# scalar field order R (4 u64)
out.append("inline constexpr Fp FR_R = %s;" % fp(consts["R"]))
# curve b (Fp) and twist b (Fp2)
out.append("inline constexpr Fp  E_B = %s;" % fp(consts["E_B"]))
out.append("inline constexpr Fp2 ETWISTED_B = %s;" % fp2(consts["ETWISTED_B"]))
# Frobenius gammas: γ1x, γ3x are Fp2 (8 words); γ2x are Fp (4 words)
for i in range(1, 6):
    out.append("inline constexpr Fp2 FROB_G1%d = %s;" % (i, fp2(consts["FROBENIUS_GAMMA1%d" % i])))
for i in range(1, 6):
    out.append("inline constexpr Fp  FROB_G2%d = %s;" % (i, fp(consts["FROBENIUS_GAMMA2%d" % i])))
for i in range(1, 6):
    out.append("inline constexpr Fp2 FROB_G3%d = %s;" % (i, fp2(consts["FROBENIUS_GAMMA3%d" % i])))
out.append("} // namespace zeg::bn")
open(sys.argv[1] if len(sys.argv) > 1 else "/dev/stdout", "w").write("\n".join(out) + "\n")
sys.stderr.write("wrote bn254 constants\n")
