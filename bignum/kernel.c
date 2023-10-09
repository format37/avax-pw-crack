#include <stdio.h>
#include "bignum.h"

__global__ void testKernel() {
  BN_CTX *ctx = BN_CTX_new();

  // Addition
  BIGNUM a;
  BIGNUM b;
  BIGNUM c;

  BN_ULONG a_d[8];
  BN_ULONG b_d[8]; 
  BN_ULONG c_d[16];

  // Initialize a
  // C17747B1566D9FE8AB7087E3F0C50175B788A1C84F4C756C405000A0CA2248E1
  a_d[0] = 0xC17747B1;
  a_d[1] = 0x566D9FE8;
  a_d[2] = 0xAB7087E3;
  a_d[3] = 0xF0C50175;
  a_d[4] = 0xB788A1C8;
  a_d[5] = 0x4F4C756C;
  a_d[6] = 0x405000A0;
  a_d[7] = 0xCA2248E1;  
  a.d = a_d; 
  a.top = 8;
  a.neg = 0;

  // Initialize b
  // 6C91CEA9CF0CAC55A7596D16B56D2AEFD204BB99DD677993158A7E6564F93CDF
  b_d[0] = 0x6C91CEA9;
  b_d[1] = 0xCF0CAC55;
  b_d[2] = 0xA7596D16;
  b_d[3] = 0xB56D2AEF;
  b_d[4] = 0xD204BB99;
  b_d[5] = 0xDD677993;
  b_d[6] = 0x158A7E65;
  b_d[7] = 0x64F93CDF;
  b.d = b_d;
  b.neg = 0;
  b.top = 8;
  // Print inputs
  bn_print("A: ", &a);
  bn_print("B: ", &b);
  
  // Initialize c
  for (int i = 0; i < 16; i++) c_d[i] = 0;
  c.d = c_d;
  c.neg = 0;
  c.top = 16;

  // Add A and B
  bn_add(&a, &b, &c);
  
  // Print A + B
  bn_print("A + B: ", &c);

  // Modular Reduction
  BIGNUM m;
  BN_ULONG m_d[8];
  for (int i = 0; i < 8; i++) m_d[i] = 0;
  m_d[0] = 0x00000064; // 100
  m.d = m_d;
  m.top = 1;
  m.neg = 0;
  // m_d[0] = 0x00000064; // 100
  // Print M
  bn_print("M: ", &m);

  // Result 
  // BN_ULONG res;  
  // bn_mod(&c, &m, &c, 1);
  // BN_mod(&c, &c, &m, ctx);
  // Call BN_mod correctly
  // BN_mod(&rem, &c, &m, ctx);
  // BN_nnmod(&c, &c, &m, ctx);
  // res = bn_mod_big_signed(&c, &m);
  // int bn_mod(BIGNUM *rm, const BIGNUM *num, const BIGNUM *divisor)
  
  // Initialize rm
  /*BIGNUM rm;
  BN_ULONG rm_d[8];
  for (int i = 0; i < 8; i++) rm_d[i] = 0;*/

  //bn_print("rm: ", &rm);

  //res = bn_mod(&c, &m, 1);
  // void bn_mod_curveOrder(uint32_t result[8], const uint32_t num[16])
  bn_mod_curveOrder(&m, &c);
  
  // Print C mod M
  // printf("C mod M: %02x\n", res);
  // printf("C mod M: %02x\n", bn_mod(&c, &m, 1));
  bn_print("M: ", &m);

  BN_CTX_free(ctx);
}
