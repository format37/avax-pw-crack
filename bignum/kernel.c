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
  BN_ULONG c_d[20];

  // Initialize a and b
  a.d = a_d; 
  /*a.top = 1; 
  a.d[0] = 70;*/
  a.top = 8;
  a.neg = 0;
  // C17747B1566D9FE8AB7087E3F0C50175B788A1C84F4C756C405000A0CA2248E1
  a.d[0] = 0xC17747B1;
  a.d[1] = 0x566D9FE8; 
  a.d[2] = 0xAB7087E3;
  a.d[3] = 0xF0C50175;
  a.d[4] = 0xB788A1C8;
  a.d[5] = 0x4F4C756C;
  a.d[6] = 0x405000A0;
  a.d[7] = 0xCA2248E1;
  
  b.d = b_d;
  b.neg = 0;
  /*b.top = 1;
  b.d[0] = 50;*/
  b.top = 8;
  // 6C91CEA9CF0CAC55A7596D16B56D2AEFD204BB99DD677993158A7E6564F93CDF
  b.d[0] = 0x6C91CEA9;
  b.d[1] = 0xCF0CAC55;
  b.d[2] = 0xA7596D16;
  b.d[3] = 0xB56D2AEF;
  b.d[4] = 0xD204BB99;
  b.d[5] = 0xDD677993;
  b.d[6] = 0x158A7E65;
  b.d[7] = 0x64F93CDF;

  // Print inputs
  bn_print("A: ", &a);
  bn_print("B: ", &b);
  
  // Add A and B
  c.d = c_d;
  c.neg = 0;
  c.top = 8;
  c.d[0] = 0;
  c.d[1] = 0;
  c.d[2] = 0;
  c.d[3] = 0;
  c.d[4] = 0;
  c.d[5] = 0;
  c.d[6] = 0;
  c.d[7] = 0;
  

  bn_add(&a, &b, &c);
  
  // Print A + B
  bn_print("A + B: ", &c);

  // Modular Reduction
  BIGNUM m;
  BN_ULONG m_d[10];
  m.d = m_d;
  m.top = 1;
  m.neg = 0;
  m_d[0] = 0x00000064; // 100

  // Print M
  bn_print("M: ", &m);

  // Result 
  BN_ULONG res;
  
  // bn_mod(&c, &m, &c, 1);
  // BN_mod(&c, &c, &m, ctx);
  // Call BN_mod correctly
  // BN_mod(&rem, &c, &m, ctx);
  // BN_nnmod(&c, &c, &m, ctx);
  res = bn_mod_big_signed(&c, &m);
  
  // Print C mod M
  printf("C mod M: %02x\n", res);

  BN_CTX_free(ctx);
}
