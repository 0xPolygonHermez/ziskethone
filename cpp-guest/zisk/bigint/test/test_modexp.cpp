// test_modexp.cpp — host test of modexp_compute vs Python pow(b,e,m). Auto-generated.
#include <cstdio>
#include <cstdint>
#include "../modexp.hpp"
using namespace zeg::bi;
static int g_fail=0; static void check(bool ok,const char*n){std::printf("%s %s\n",ok?"ok  ":"FAIL",n);if(!ok)++g_fail;}
static const uint8_t b0[]={3}; static const int b0_n=1;
static const uint8_t e0[]={5}; static const int e0_n=1;
static const uint8_t m0[]={7}; static const int m0_n=1;
static const uint8_t o0[]={5}; static const int o0_n=1;
static const uint8_t b1[]={0}; static const int b1_n=1;
static const uint8_t e1[]={0}; static const int e1_n=1;
static const uint8_t m1[]={5}; static const int m1_n=1;
static const uint8_t o1[]={1}; static const int o1_n=1;
static const uint8_t b2[]={7}; static const int b2_n=1;
static const uint8_t e2[]={0}; static const int e2_n=1;
static const uint8_t m2[]={13}; static const int m2_n=1;
static const uint8_t o2[]={1}; static const int o2_n=1;
static const uint8_t b3[]={5}; static const int b3_n=1;
static const uint8_t e3[]={3}; static const int e3_n=1;
static const uint8_t m3[]={1}; static const int m3_n=1;
static const uint8_t o3[]={0}; static const int o3_n=1;
static const uint8_t b4[]={0}; static const int b4_n=1;
static const uint8_t e4[]={9}; static const int e4_n=1;
static const uint8_t m4[]={11}; static const int m4_n=1;
static const uint8_t o4[]={0}; static const int o4_n=1;
static const uint8_t b5[]={7,91,205,21}; static const int b5_n=4;
static const uint8_t e5[]={58,222,104,177}; static const int e5_n=4;
static const uint8_t m5[]={59,154,202,7}; static const int m5_n=4;
static const uint8_t o5[]={38,228,253,14}; static const int o5_n=4;
static const uint8_t b6[]={210,63,8,36,18,139,47,51,12,92,127,208,166,163,164,80,101,19,39,14,38,158,13,55,242,167,77,228,82,230,180,56}; static const int b6_n=32;
static const uint8_t e6[]={54,246,117,204,129,231,78,245,232,226,93,148,14,217,4,117,149,49,152,93,93,157,201,248,24,24,232,17,137,47,144,43}; static const int e6_n=32;
static const uint8_t m6[]={141,17,110,206,23,56,247,217,61,156,23,36,17,226,11,143,107,13,84,155,111,3,103,90,22,0,163,90,9,153,80,217}; static const int m6_n=32;
static const uint8_t o6[]={76,240,14,13,239,104,11,164,91,241,177,123,224,224,204,89,67,201,198,112,225,251,237,92,190,125,252,63,214,171,21,109}; static const int o6_n=32;
static const uint8_t b7[]={36,237,230,164,107,76,178,66,74,35,213,150,34,23,190,173,219,196,150,203,142,129,151,62,11,236,215,176,56,152,209,144,249,235,218,204,12,177,226,156,101,140,218,20,149,230,10,245,147,189,4,207,15,214,48,241,242,157,13,169,149,63,72,241,160,159,118,181,161,112,179,56,57,38,48,89,242,140,16,93,31,177,124,35,144,193,146,207,211,172,148,175,15,33,221,182,108,173,74,38}; static const int b7_n=100;
static const uint8_t e7[]={0,0,9,78,26,97,219,226,46,68,21,139,174,151,186,148,208,237,168,47,143,109,5,88,78,248,170,56,146,39,102,88,30,39,161,192,138,106,99,236}; static const int e7_n=40;
static const uint8_t m7[]={198,109,118,176,126,136,30,209,98,174,46,177,84,127,21,5,36,52,185,181,223,158,119,105,177,15,66,5,180,144,122,112,195,16,18,240,55,182,76,228,34,140,56,251,41,24,241,53,210,95,85,114,3,48,24,80,197,163,143,213,71,146,58,115,105}; static const int m7_n=65;
static const uint8_t o7[]={80,142,71,54,27,205,83,244,54,99,161,185,121,91,176,188,158,185,110,121,70,62,7,135,12,188,186,147,63,242,217,139,199,216,184,167,105,228,52,151,191,236,193,41,100,208,129,72,208,79,15,143,141,140,238,160,142,213,157,128,224,188,72,218,52}; static const int o7_n=65;
static const uint8_t b8[]={0,0,7,46,108,195,186,188,237,32,87,238,5,205,224,9,2,199,126,191,242,6,134,115,71,33,76,221,32,85,147,13,110,175,20,244,115,63,62,125,27,251,199,162,234,32,178,241,76,148,46,5,49,154,203,92,116,39,63,152,226,119,76,189,135,173,92,144,169,88,116,3,228,48,236,102,167,135,149,231,97,209,119,49,175,16,80,107,242,239}; static const int b8_n=90;
static const uint8_t e8[]={0,0,0,0,0,107,131,14,7,188,30,57,143,16,18,189,74,206,250,236,189,56,155,228,188,252,73,182,74,8}; static const int e8_n=30;
static const uint8_t m8[]={1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}; static const int m8_n=65;
static const uint8_t o8[]={0,17,68,210,79,187,15,111,96,253,69,248,107,111,110,200,180,66,122,252,82,13,23,220,112,140,102,21,32,181,119,208,43,123,208,126,236,251,158,215,250,146,215,129,0,74,103,219,192,156,10,205,29,232,86,113,67,204,64,35,131,84,45,36,129}; static const int o8_n=65;
static const uint8_t b9[]={121,94,130,41,69,26,189,129,241,214,158,214,23,245,232,55,215,8,32,254,17,154,114,209,116,201,223,106,204,1,28,221,148,116,3,27,127,38,20,75,152,40,159,205,89,165,74,123,177,254,224,143,87,18,66,66,80,81,193,204,209,127,154,202,224,31,80,87,202,2,19,94,146,177,211,242,142,222,13,122,195,186,234,158,19,222,239,134,171,16,49,208,246,70,225,244,10,9,124,151,107,244,108,105,125,44,175,130,238,234,203,226,38,232,117,85,87,144,248,46,193,211,252,255,42,58,244,212}; static const int b9_n=128;
static const uint8_t e9[]={165,170,60,129,79,66,109,203,179,148,251,54,187,45,66,15,15,136,8,11,16,163,214,178,170,5,225,26,178,113,89,69}; static const int e9_n=32;
static const uint8_t m9[]={0,0,10,178,227,21,18,136,98,195,58,79,183,116,235,82,72,219,64,175,114,21,131,112,210,105,169,165,174,101,143,51,254,59,137,11,147,244,72,179}; static const int m9_n=40;
static const uint8_t o9[]={0,0,3,247,171,243,253,235,249,41,174,214,136,52,134,242,192,251,157,250,60,29,213,158,119,69,70,230,75,123,219,240,173,36,197,210,74,141,182,210}; static const int o9_n=40;
int main(){ uint8_t out[256]; bool ok;
  modexp_compute(b0,b0_n,e0,e0_n,m0,m0_n,out); ok=true; for(int k=0;k<o0_n;++k) if(out[k]!=o0[k]) ok=false; check(ok,"3^5 mod 7");
  modexp_compute(b1,b1_n,e1,e1_n,m1,m1_n,out); ok=true; for(int k=0;k<o1_n;++k) if(out[k]!=o1[k]) ok=false; check(ok,"0^0 mod 5 =1");
  modexp_compute(b2,b2_n,e2,e2_n,m2,m2_n,out); ok=true; for(int k=0;k<o2_n;++k) if(out[k]!=o2[k]) ok=false; check(ok,"7^0 mod 13 =1");
  modexp_compute(b3,b3_n,e3,e3_n,m3,m3_n,out); ok=true; for(int k=0;k<o3_n;++k) if(out[k]!=o3[k]) ok=false; check(ok,"x mod 1 =0");
  modexp_compute(b4,b4_n,e4,e4_n,m4,m4_n,out); ok=true; for(int k=0;k<o4_n;++k) if(out[k]!=o4[k]) ok=false; check(ok,"0^9 mod 11 =0");
  modexp_compute(b5,b5_n,e5,e5_n,m5,m5_n,out); ok=true; for(int k=0;k<o5_n;++k) if(out[k]!=o5[k]) ok=false; check(ok,"32-bitish");
  modexp_compute(b6,b6_n,e6,e6_n,m6,m6_n,out); ok=true; for(int k=0;k<o6_n;++k) if(out[k]!=o6[k]) ok=false; check(ok,"256-bit odd");
  modexp_compute(b7,b7_n,e7,e7_n,m7,m7_n,out); ok=true; for(int k=0;k<o7_n;++k) if(out[k]!=o7[k]) ok=false; check(ok,"long odd");
  modexp_compute(b8,b8_n,e8,e8_n,m8,m8_n,out); ok=true; for(int k=0;k<o8_n;++k) if(out[k]!=o8[k]) ok=false; check(ok,"long even (2^512)");
  modexp_compute(b9,b9_n,e9,e9_n,m9,m9_n,out); ok=true; for(int k=0;k<o9_n;++k) if(out[k]!=o9[k]) ok=false; check(ok,"base>mod");
  std::printf(g_fail?"\n%d FAILED\n":"\nALL PASS\n",g_fail); return g_fail?1:0; }
