

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <byteswap.h>

#include "blst/bindings/blst.h"
#include <byteswap.h>



// hex string to int array conversion
// input is string of hex characters, without 0x prefix
// also converts to little endian (ie least significant byte first)
void hexstr_to_bytearray(uint8_t* out, char* in){
  //printf("hexstr_to_intarray(%s)\n",in);
  size_t len = strlen(in);
  uint8_t byte = 0;
  uint8_t nibble = 0;
  int i;
  for (i=len-1; i>=0 ;i--){
    nibble = in[i];
    if (nibble >= '0' && nibble <= '9') nibble = nibble - '0';
    else if (nibble >= 'a' && nibble <='f') nibble = nibble - 'a' + 10;
    else if (nibble >= 'A' && nibble <='F') nibble = nibble - 'A' + 10;
    else printf("ERROR: %s is not hex string.\n",in);
    if (!((i+len%2)%2)) {
      byte = (nibble<<4) + byte;
      *(out+(len-i)/2-1) = byte;
      byte=0;
    }
    else byte = nibble;
  }
  if (byte)
    *(out+(len-i)/2-1) = byte;
}







// print 48 bytes
const int print_endianness_flag = 0;	// 0 for little-endain, 1 for big-endian
const int print_spacing_flag = 1;	// 0 for no space, 1 for new line after 48 bytes
void f1print(uint64_t* p){
  //printf("    a += bytearray.fromhex(\""); 
  if(print_endianness_flag){
    // big-endian
    for (int i=5;i>=0;i--)
      printf("%016lx",(p)[i]);
  } else {
    // little-endian
    for (int i=0;i<6;i++)
      printf("%016lx",bswap_64((p)[i]));
  }
  //printf("\")[::-1]");
  if (print_spacing_flag)
    printf("\n");
}
void f2print(uint64_t* p){
  f1print(p);
  f1print(p+6);
}
void f6print(uint64_t* p){
  f2print(p);
  f2print(p+12);
  f2print(p+24);
}
void f12print(uint64_t* p){
  f6print(p);
  f6print(p+36);
}





// execute pairing and print inputs/outputs
void miller_loop_and_final_exp(uint8_t* P, uint8_t* Q){
  printf("input:\n");
  f2print((uint64_t*)P);
  f2print((uint64_t*)Q);
  f2print((uint64_t*)(Q+48*2));
  
  blst_fp12 *fp12_miller_loop = malloc(48*12);
  blst_miller_loop(fp12_miller_loop, (blst_p2_affine*)Q, (blst_p1_affine*)P);
  printf("\nmiller loop output (and final exponentiation input):\n");
  f12print((uint64_t*)fp12_miller_loop);
  
  blst_fp12 *fp12_final_exp = malloc(48*12);
  blst_final_exp(fp12_final_exp, fp12_miller_loop);
  printf("\nfinal exponentiation output:\n");
  f12print((uint64_t*)fp12_final_exp);
  printf("\n");
}





void test1(){
  // negative generators from blst/src/e2.c and blst/src/e1.c
  uint8_t P[2*48];
  uint8_t Q[4*48];
  uint8_t* P0 = P;
  uint8_t* P1 = P+48;
  uint8_t* Q0 = Q;
  uint8_t* Q1 = Q0+48;
  uint8_t* Q2 = Q1+48;
  uint8_t* Q3 = Q2+48;
  hexstr_to_bytearray(P0,"120177419e0bfb75edce6ecc21dbf440f0ae6acdf3d0e747154f95c7143ba1c17817fc679976fff55cb38790fd530c16");
  hexstr_to_bytearray(P1,"0e44d2ede97744303cff1b76964b531712caf35ba344c12a89d7738d9fa9d05592899ce4383b0270ff526c2af318883a");
  hexstr_to_bytearray(Q0,"058191924350bcd76f67b7631863366b9894999d1a3caee9a1a893b53e2ae580b3f5fb2687b4961af5f28fa202940a10");
  hexstr_to_bytearray(Q1,"11922a097360edf3c2b6ed0ef21585471b1ab6cc8541b3673bb17e18e2867806aaa0c59dbccd60c3a5a9c0759e23f606");
  hexstr_to_bytearray(Q2,"197d145bbaff0bb54347fe40525c8734a887959b8577c95f7f4a4d344ca692c9c52f05df531d63a56d8bf5079fb65e61");
  hexstr_to_bytearray(Q3,"0ed54f48d5a1caa764044f659f0ee1e9eb2def362a476f84e0832636bacc0a840601d8f4863f9e230c3e036d209afa4e");
  
  miller_loop_and_final_exp(P,Q);
}

void test2(){
  // identity elements from https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2539.md#specification
  uint8_t P[2*48];
  uint8_t Q[4*48];
  uint8_t* P0 = P;
  uint8_t* P1 = P+48;
  uint8_t* Q0 = Q;
  uint8_t* Q1 = Q0+48;
  uint8_t* Q2 = Q1+48;
  uint8_t* Q3 = Q2+48;
  hexstr_to_bytearray(P0,"008848defe740a67c8fc6225bf87ff5485951e2caa9d41bb188282c8bd37cb5cd5481512ffcd394eeab9b16eb21be9ef");
  hexstr_to_bytearray(P1,"01914a69c5102eff1f674f5d30afeec4bd7fb348ca3e52d96d182ad44fb82305c2fe3d3634a9591afd82de55559c8ea6");
  hexstr_to_bytearray(Q0,"018480be71c785fec89630a2a3841d01c565f071203e50317ea501f557db6b9b71889f52bb53540274e3e48f7c005196");
  hexstr_to_bytearray(Q1,"00ea6040e700403170dc5a51b1b140d5532777ee6651cecbe7223ece0799c9de5cf89984bff76fe6b26bfefa6ea16afe");
  hexstr_to_bytearray(Q2,"00690d665d446f7bd960736bcbb2efb4de03ed7274b49a58e458c282f832d204f2cf88886d8c7c2ef094094409fd4ddf");
  hexstr_to_bytearray(Q3,"00f8169fd28355189e549da3151a70aa61ef11ac3d591bf12463b01acee304c24279b83f5e52270bd9a1cdd185eb8f93");

  miller_loop_and_final_exp(P,Q);
}

void test3(){
  // from wasmsnark/test
  // uncommented miller loop inputs/output in test/bls12381.js
  // cd wasmsnark && ~/repos/node/node-v12.18.4-linux-x64/bin/npx mocha test/bls12381.js
  uint8_t P[2*48];
  uint8_t Q[4*48];
  uint8_t* P0 = P;
  uint8_t* P1 = P+48;
  uint8_t* Q0 = Q;
  uint8_t* Q1 = Q0+48;
  uint8_t* Q2 = Q1+48;
  uint8_t* Q3 = Q2+48;
  hexstr_to_bytearray(P0,"0f81da25ecf1c84b577fefbedd61077a81dc43b00304015b2b596ab67f00e41c86bb00ebd0f90d4b125eb0539891aeed");
  hexstr_to_bytearray(P1,"11af629591ec86916d6ce37877b743fe209a3af61147996c1df7fd1c47b03181cd806fd31c3071b739e4deb234bd9e19");
  hexstr_to_bytearray(Q0,"024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8");
  hexstr_to_bytearray(Q1,"13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e");
  hexstr_to_bytearray(Q2,"0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801");
  hexstr_to_bytearray(Q3,"0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be");

  miller_loop_and_final_exp(P,Q);
}

void test4(){
  // from https://tools.ietf.org/id/draft-yonezawa-pairing-friendly-curves-02.html#rfc.appendix.B
  uint8_t P[2*48];
  uint8_t Q[4*48];
  uint8_t* P0 = P;
  uint8_t* P1 = P+48;
  uint8_t* Q0 = Q;
  uint8_t* Q1 = Q0+48;
  uint8_t* Q2 = Q1+48;
  uint8_t* Q3 = Q2+48;
  hexstr_to_bytearray(P0,"17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb");
  hexstr_to_bytearray(P1,"08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1");
  hexstr_to_bytearray(Q0,"024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8");
  hexstr_to_bytearray(Q1,"13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e");
  hexstr_to_bytearray(Q2,"0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801");
  hexstr_to_bytearray(Q3,"0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be");

  miller_loop_and_final_exp(P,Q);
}





int main(int argc,char**argv){

  printf("\ntest1:\n");
  test1();
  printf("\ntest2:\n");
  test2();
  printf("\ntest3:\n");
  test3();
  printf("\ntest4:\n");
  test4();

  return 0;
}

