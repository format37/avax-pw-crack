#include <stdio.h>
#include "bn.h"

#define BN_MASK2 0xffffffff;

typedef struct bignum_st {
  BN_ULONG *d;
  int top;
  int dmax;
  int neg;
  int flags;
} BIGNUM;

__device__ void bn_print(char* msg, BIGNUM* a) {
  printf("%s", msg);
  for(int i=0; i<a->top; i++) {
    printf("%02x", a->d[i]);
  }
  printf("\n");
}

__device__ void bn_add(BIGNUM* a, BIGNUM* b, BIGNUM* r) {

  int max = a->top > b->top ? a->top : b->top;

  for(int i=0; i<max; i++) {
    r->d[i] = a->d[i] + b->d[i]; 
  }

  // Set result top
  r->top = a->top;
  if (b->top > a->top) {
    r->top = b->top; 
  }
}

__device__ BN_ULONG bn_mod(BN_ULONG num, BN_ULONG divisor) {
  return num % divisor; 
}

__device__ BN_ULONG bn_mod_big(BIGNUM *num, BIGNUM *divisor) {

  BN_ULONG d = divisor->d[divisor->top-1]; // divisor
  BN_ULONG n = num->d[num->top-1]; // numerator
  
  return bn_mod(n, d);
}

__device__ BN_ULONG bn_mod_big_signed(BIGNUM *num, BIGNUM *divisor) {

  int numNeg = num->neg;
  int divNeg = divisor->neg;

  BN_ULONG d = divisor->d[divisor->top-1]; 
  BN_ULONG n = num->d[num->top-1];

  BN_ULONG res = bn_mod(n, d);

  if (numNeg) {
    res = d - res; // subtract from divisor
  }

  if (divNeg) {
    res = -res; // negate result if divisor is negative
  }

  return res;

}

__global__ void testKernel() {
  BN_CTX *ctx = BN_CTX_new();

  // Addition
  BIGNUM a;
  BIGNUM b;
  BIGNUM c;

  BN_ULONG a_d[10];
  BN_ULONG b_d[10]; 
  BN_ULONG c_d[20];

  // Initialize a and b
  a.d = a_d; 
  a.top = 1; 
  a.d[0] = 70;
  b.d = b_d;
  b.top = 1;
  b.d[0] = 50;

  // Print inputs
  bn_print("A: ", &a);
  bn_print("B: ", &b);
  
  // Add A and B
  c.d = c_d;
  c.top = 1;
  c.neg = 0;
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
