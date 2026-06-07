// test_bignum_long.cpp — host test for the MODEXP long-path arithmetic.
//   c++ -std=c++20 -O2 -I.. test_bignum_long.cpp -o /tmp/t && /tmp/t
// KATs (mul·mod, square·mod, rem) precomputed with Python arbitrary-precision.

#include <cstdio>
#include <cstdint>
#include "../bignum.hpp"
using namespace zeg::bi;
static int g_fail=0;
static void check(bool ok,const char*n){std::printf("%s %s\n",ok?"ok  ":"FAIL",n);if(!ok)++g_fail;}
static bool eqw(const uint64_t*a,int la,const uint64_t*b,int lb){ if(la!=lb)return false; for(int i=0;i<la*4;++i) if(a[i]!=b[i])return false; return true; }
static const uint64_t A0[]={0x1c80317fa3b1799dULL,0xbdd640fb06671ad1ULL,0x3eb13b9046685257ULL,0x23b8c1e9392456deULL,0x1a3d1fa7bc8960a9ULL,0xbd9c66b3ad3c2d6dULL,0x8b9d2434e465e150ULL,0x972a846916419f82ULL,0x0822e8f36c031199ULL,0x000000000007a0caULL,0x0000000000000000ULL,0x0000000000000000ULL}; static const int A0_w=3;
static const uint64_t B0[]={0x37f8a88b17fc695aULL,0x815ef6d13b8faa18ULL,0x06cb0fb39a1de644ULL,0x32e706298fadc1a6ULL,0xa65ed389b74d0fb1ULL,0x8b8148f6b38a088cULL,0x0000000000006b65ULL,0x0000000000000000ULL}; static const int B0_w=2;
static const uint64_t M0[]={0x72ff5d2a386ecbe1ULL,0x4737819096da1dacULL,0xde8a774bcf36d58bULL,0xc241330b01a9e71fULL,0x28df6ec4ce4a2bbdULL,0x6c307511b2b9437aULL,0x47229389571aa876ULL,0x000371ec27cd8130ULL}; static const int M0_w=2;
static const uint64_t MUL0[]={0x8acc57dce23cb3baULL,0x7b3ff88361bf92d4ULL,0xf5c8fa728aa356b3ULL,0x026a2ea2521284dcULL,0xb6589325c54a6ef7ULL,0x5097b7c0820dee8bULL,0xafaa6b7201df0d9fULL,0x0000aa23808893c8ULL}; static const int MUL0_w=2;
static const uint64_t SQ0[]={0x0e5c8384dd88fe74ULL,0x4555a87de844258dULL,0xe2999786e3afd181ULL,0x98768474ec919e49ULL,0x41c7c7c2688f2636ULL,0x26b979d52588dc65ULL,0xb77626525aca7709ULL,0x000339be6270f82bULL}; static const int SQ0_w=2;
static const uint64_t REM0[]={0x58c6b2656860e5f7ULL,0x3559b062542c037bULL,0x6b4c61b705ed1aecULL,0xa2e8791a1504142dULL,0x47c89b779c6d3e99ULL,0xc9ebd663af94dfebULL,0x686979d409e34197ULL,0x00030775fdda47f5ULL}; static const int REM0_w=2;
static const uint64_t A1[]={0xc37459eef50bea63ULL,0x1a2a73ed562b0f79ULL,0x6142ea7d17be3111ULL,0x5be6128e18c26797ULL,0x580d7b71d8f56413ULL,0x43b7a3a69a8dca03ULL,0x0b1f9163ce9ff57fULL,0x759cde66bacfb3d0ULL,0x1ff49b7889463e85ULL,0x0000000000f91e1dULL,0x0000000000000000ULL,0x0000000000000000ULL}; static const int A1_w=3;
static const uint64_t B1[]={0x60e7a113ec1b8ca1ULL,0x8d5288f1142c3fe8ULL,0xd453dd324b0dbb41ULL,0x9e574f7aa0ee89aeULL,0xdc98d2c1e2acf72fULL,0x93cd59bf5c941cf0ULL,0x0000000000003139ULL,0x0000000000000000ULL}; static const int B1_w=2;
static const uint64_t M1[]={0x11ce5dd2b45ed1f1ULL,0xa9488d990bbb2599ULL,0xc5e7ce8a3a578a8eULL,0xfc377a4c4a15544dULL,0xdaf61a26146d3f31ULL,0xddd1dfb23b982ef8ULL,0x614ff3d719db3ad0ULL,0x0007412b47294739ULL}; static const int M1_w=2;
static const uint64_t MUL1[]={0xd91dc0ab49c7d47fULL,0xe773505f85b4038dULL,0x12931dc47f39cd4bULL,0x889498de23ba0128ULL,0x4b8b3b694c019687ULL,0x16eeeb9d6b6d60e6ULL,0xf82a0810c5d7aebcULL,0x0001eb3be123e3bbULL}; static const int MUL1_w=2;
static const uint64_t SQ1[]={0x115daa43fd31ddffULL,0x67a5bb166356d255ULL,0x9ea8219211a1eb4cULL,0x3644e0b0f22f54d2ULL,0x42358cfa355f7635ULL,0x4d74e682e8e8ffc8ULL,0x26ea85f54f92cccbULL,0x00053708d867982fULL}; static const int SQ1_w=2;
static const uint64_t REM1[]={0x8a4b13ce7424c462ULL,0x8c071ab6d4e492afULL,0x68fd1ce4ac9eaa5dULL,0x637b76cad399aadaULL,0xbf993eaa9d4a373aULL,0xf729c66ba99582a3ULL,0x0c355d0294a9c7ffULL,0x0001dcd1d2484731ULL}; static const int REM1_w=2;
static const uint64_t A2[]={0xd58842dea2bc372fULL,0x29a3b2e95d65a441ULL,0x5af305535ec42e08ULL,0xab9099a435a240aeULL,0xb3aa7efe4458a885ULL,0xaefcfad8efc89849ULL,0x12476f57a5e5a5abULL,0xa28defe39bf00273ULL,0x88bd64072bcfbe01ULL,0x0000000000baa80dULL,0x0000000000000000ULL,0x0000000000000000ULL}; static const int A2_w=3;
static const uint64_t B2[]={0x29d4beef3eabedcbULL,0x6123fdf77656af72ULL,0xfd5166e6451b4cf3ULL,0xa3d70628ece66fa2ULL,0x8e944239b02b61c4ULL,0xaf42e12f3838b326ULL,0x0000000000005304ULL,0x0000000000000000ULL}; static const int B2_w=2;
static const uint64_t M2[]={0xc4b032ccd7c524a5ULL,0x0e51f30dc6a7ee39ULL,0xd261a7ab3aa2e4f9ULL,0xce177b4e0837b8a3ULL,0x66b2bc5b50c187fcULL,0x10f1bc81448aaa9eULL,0xe9c349e03602f8acULL,0x0009132bf16287e4ULL}; static const int M2_w=2;
static const uint64_t MUL2[]={0x151fbdb7149de3cbULL,0x5ffdc8dbcb19e47cULL,0x8f2120100f311249ULL,0xbf9bcd37d296a516ULL,0x7878f76dca2fd772ULL,0x27557b16d35a8d01ULL,0xc3a365c689778569ULL,0x000242a808c67adcULL}; static const int MUL2_w=2;
static const uint64_t SQ2[]={0x3cec5e8135b0bc15ULL,0xd0152b76831d2525ULL,0xb6e758c3ff900276ULL,0x26cf9a5b9d604a1fULL,0x941f3e85ca8de445ULL,0x7a0e7a636d6a7ef7ULL,0x52d8c7ad7bcc1e6aULL,0x0005bb8709cf0098ULL}; static const int SQ2_w=2;
static const uint64_t REM2[]={0x02dbc2186de72bb3ULL,0x9c9847eb84770380ULL,0x3ce30b8b92e5c16bULL,0x642b73210009865dULL,0x342b7eb8f8b7ae16ULL,0x53f16593393da5bbULL,0x575de70d7430c720ULL,0x00036bcf9177b52fULL}; static const int REM2_w=2;
static const uint64_t A3[]={0xb7c93acfe059a0eeULL,0x366eb16f508ebad7ULL,0x7fcd9eb1a7cad415ULL,0xe27a984d654821d0ULL,0xa491f0b2ea1fca65ULL,0x24933b83757750a9ULL,0x23bed01d43cf2fdeULL,0xbeb799193f22faf8ULL,0x89fa6a688fb5d27bULL,0x0000000000434308ULL,0x0000000000000000ULL,0x0000000000000000ULL}; static const int A3_w=3;
static const uint64_t B3[]={0x95a76d79bf3c4c06ULL,0xe5d7b8756dadd6c7ULL,0x663f1c97956269f0ULL,0x382567b85cabcc97ULL,0xff5e9ff0ff50bde4ULL,0x827050a82369b584ULL,0x0000000000007e57ULL,0x0000000000000000ULL}; static const int B3_w=2;
static const uint64_t M3[]={0xc17af08a1745d6d9ULL,0xdc713d960c0fd195ULL,0x27209bdf1c11f735ULL,0x28f49481a0a04dc4ULL,0xae340454cac5b68cULL,0x98ae43346c12ace8ULL,0x62801c4510435a10ULL,0x000988c261b1cd22ULL}; static const int M3_w=2;
static const uint64_t MUL3[]={0x4523088f081df9adULL,0xbb8a36ecb9a8bd22ULL,0xcbb75af4d7348e68ULL,0xe8d678084f6da829ULL,0x2406b914cc3a9098ULL,0xc5ce432ac3d0e60cULL,0x8a7f44895616eec7ULL,0x0000b4462f9e73f9ULL}; static const int MUL3_w=2;
static const uint64_t SQ3[]={0x9f040992282c47f7ULL,0x242549be8b703fd4ULL,0xd0bf48b505c9195cULL,0x528909938f41d492ULL,0x453edd07c75bd879ULL,0xe5a2a400800f63daULL,0x1afabd5520fc76d7ULL,0x000614b451f09817ULL}; static const int SQ3_w=2;
static const uint64_t REM3[]={0x4f4e8b5d29dd5a73ULL,0x25b9abe383def1faULL,0x68ca4687fc36fc2fULL,0x2b77864b09022be7ULL,0x1075f6a8bbcc3d87ULL,0x26bd4f88b3bda423ULL,0xee9c72fb14ab4e86ULL,0x00076f6ed109e513ULL}; static const int REM3_w=2;
int main(){
  const uint64_t* A[]={A0,A1,A2,A3}; const int Aw[]={A0_w,A1_w,A2_w,A3_w};
  const uint64_t* B[]={B0,B1,B2,B3}; const int Bw[]={B0_w,B1_w,B2_w,B3_w};
  const uint64_t* M[]={M0,M1,M2,M3}; const int Mw[]={M0_w,M1_w,M2_w,M3_w};
  const uint64_t* MUL[]={MUL0,MUL1,MUL2,MUL3}; const int MULw[]={MUL0_w,MUL1_w,MUL2_w,MUL3_w};
  const uint64_t* SQ[]={SQ0,SQ1,SQ2,SQ3}; const int SQw[]={SQ0_w,SQ1_w,SQ2_w,SQ3_w};
  const uint64_t* REM[]={REM0,REM1,REM2,REM3}; const int REMw[]={REM0_w,REM1_w,REM2_w,REM3_w};
  for(int i=0;i<4;++i){
    uint64_t out[4*2*MAXW]; int ol;
    ol=mul_and_reduce_long(A[i],Aw[i],B[i],Bw[i],M[i],Mw[i],out);
    check(eqw(out,ol,MUL[i],MULw[i]),"mul_and_reduce_long KAT");
    ol=square_and_reduce_long(A[i],Aw[i],M[i],Mw[i],out);
    check(eqw(out,ol,SQ[i],SQw[i]),"square_and_reduce_long KAT");
    ol=rem_long(A[i],Aw[i],M[i],Mw[i],out);
    check(eqw(out,ol,REM[i],REMw[i]),"rem_long KAT");
  }
  std::printf(g_fail?"\n%d FAILED\n":"\nALL PASS\n",g_fail);
  return g_fail?1:0;
}
