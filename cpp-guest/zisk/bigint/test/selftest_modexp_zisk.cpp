// selftest_modexp_zisk.cpp — on-emulator EIP-198 modexp self-test (ZEG_ZISK). Auto-generated.
#include <cstdint>
#include "../modexp.hpp"
#include "zeg/zisk_io.hpp"
using namespace zeg::bi;
static uint32_t R=0; static int B=0; static void rec(bool ok){ if(ok) R|=(1u<<B); ++B; }
static const uint8_t b0[]={3}; static const int b0_n=1;
static const uint8_t e0[]={5}; static const int e0_n=1;
static const uint8_t m0[]={7}; static const int m0_n=1;
static const uint8_t o0[]={5}; static const int o0_n=1;
static const uint8_t b1[]={7}; static const int b1_n=1;
static const uint8_t e1[]={0}; static const int e1_n=1;
static const uint8_t m1[]={13}; static const int m1_n=1;
static const uint8_t o1[]={1}; static const int o1_n=1;
static const uint8_t b2[]={7,91,205,21}; static const int b2_n=4;
static const uint8_t e2[]={58,222,104,177}; static const int e2_n=4;
static const uint8_t m2[]={59,154,202,7}; static const int m2_n=4;
static const uint8_t o2[]={38,228,253,14}; static const int o2_n=4;
static const uint8_t b3[]={210,63,8,36,18,139,47,51,12,92,127,208,166,163,164,80,101,19,39,14,38,158,13,55,242,167,77,228,82,230,180,56}; static const int b3_n=32;
static const uint8_t e3[]={54,246,117,204,129,231,78,245,232,226,93,148,14,217,4,117,149,49,152,93,93,157,201,248,24,24,232,17,137,47,144,43}; static const int e3_n=32;
static const uint8_t m3[]={141,17,110,206,23,56,247,217,61,156,23,36,17,226,11,143,107,13,84,155,111,3,103,90,22,0,163,90,9,153,80,217}; static const int m3_n=32;
static const uint8_t o3[]={76,240,14,13,239,104,11,164,91,241,177,123,224,224,204,89,67,201,198,112,225,251,237,92,190,125,252,63,214,171,21,109}; static const int o3_n=32;
static const uint8_t b4[]={36,237,230,164,107,76,178,66,74,35,213,150,34,23,190,173,219,196,150,203,142,129,151,62,11,236,215,176,56,152,209,144,249,235,218,204,12,177,226,156,101,140,218,20,149,230,10,245,147,189,4,207,15,214,48,241,242,157,13,169,149,63,72,241,160,159,118,181,161,112,179,56,57,38,48,89,242,140,16,93,31,177,124,35,144,193,146,207,211,172,148,175,15,33,221,182,108,173,74,38}; static const int b4_n=100;
static const uint8_t e4[]={0,0,9,78,26,97,219,226,46,68,21,139,174,151,186,148,208,237,168,47,143,109,5,88,78,248,170,56,146,39,102,88,30,39,161,192,138,106,99,236}; static const int e4_n=40;
static const uint8_t m4[]={198,109,118,176,126,136,30,209,98,174,46,177,84,127,21,5,36,52,185,181,223,158,119,105,177,15,66,5,180,144,122,112,195,16,18,240,55,182,76,228,34,140,56,251,41,24,241,53,210,95,85,114,3,48,24,80,197,163,143,213,71,146,58,115,105}; static const int m4_n=65;
static const uint8_t o4[]={80,142,71,54,27,205,83,244,54,99,161,185,121,91,176,188,158,185,110,121,70,62,7,135,12,188,186,147,63,242,217,139,199,216,184,167,105,228,52,151,191,236,193,41,100,208,129,72,208,79,15,143,141,140,238,160,142,213,157,128,224,188,72,218,52}; static const int o4_n=65;
static const uint8_t b5[]={0,0,7,46,108,195,186,188,237,32,87,238,5,205,224,9,2,199,126,191,242,6,134,115,71,33,76,221,32,85,147,13,110,175,20,244,115,63,62,125,27,251,199,162,234,32,178,241,76,148,46,5,49,154,203,92,116,39,63,152,226,119,76,189,135,173,92,144,169,88,116,3,228,48,236,102,167,135,149,231,97,209,119,49,175,16,80,107,242,239}; static const int b5_n=90;
static const uint8_t e5[]={0,0,0,0,0,107,131,14,7,188,30,57,143,16,18,189,74,206,250,236,189,56,155,228,188,252,73,182,74,8}; static const int e5_n=30;
static const uint8_t m5[]={1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}; static const int m5_n=65;
static const uint8_t o5[]={0,17,68,210,79,187,15,111,96,253,69,248,107,111,110,200,180,66,122,252,82,13,23,220,112,140,102,21,32,181,119,208,43,123,208,126,236,251,158,215,250,146,215,129,0,74,103,219,192,156,10,205,29,232,86,113,67,204,64,35,131,84,45,36,129}; static const int o5_n=65;
int main(){ uint8_t out[256];
  modexp_compute(b0,b0_n,e0,e0_n,m0,m0_n,out); { bool ok=true; for(int k=0;k<o0_n;++k) if(out[k]!=o0[k]) ok=false; rec(ok); }
  modexp_compute(b1,b1_n,e1,e1_n,m1,m1_n,out); { bool ok=true; for(int k=0;k<o1_n;++k) if(out[k]!=o1[k]) ok=false; rec(ok); }
  modexp_compute(b2,b2_n,e2,e2_n,m2,m2_n,out); { bool ok=true; for(int k=0;k<o2_n;++k) if(out[k]!=o2[k]) ok=false; rec(ok); }
  modexp_compute(b3,b3_n,e3,e3_n,m3,m3_n,out); { bool ok=true; for(int k=0;k<o3_n;++k) if(out[k]!=o3[k]) ok=false; rec(ok); }
  modexp_compute(b4,b4_n,e4,e4_n,m4,m4_n,out); { bool ok=true; for(int k=0;k<o4_n;++k) if(out[k]!=o4[k]) ok=false; rec(ok); }
  modexp_compute(b5,b5_n,e5,e5_n,m5,m5_n,out); { bool ok=true; for(int k=0;k<o5_n;++k) if(out[k]!=o5[k]) ok=false; rec(ok); }
  zeg::zisk::set_output_u32(0,R); zeg::zisk::set_output_u32(1,(uint32_t)B); return 0; }
