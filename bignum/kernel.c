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

__device__ void bn_print_v1(char* msg, BIGNUM* a) {

  char buffer[1024];
  int index = 0;

  for(int i=0; i<a->top; i++) {
    
    BN_ULONG value = a->d[i];
    do {
      buffer[index++] = '0' + (value % 10);
      value /= 10;
    } while (value > 0);

    // Add separator between words
    if (i < a->top - 1) {
      buffer[index++] = ','; 
    }
  }

  // Add string terminator
  buffer[index] = '\0';

  // Reverse string
  for(int i=0; i<index/2; i++) {
    char tmp = buffer[i];
    buffer[i] = buffer[index-i-1];
    buffer[index-i-1] = tmp;
  }

  printf("%s%s\n", msg, buffer);

}

__device__ void bn_add_v0(BIGNUM* a, BIGNUM* b, BIGNUM* r) {
  int max = a->top > b->top ? a->top : b->top;
  for(int i=0; i<max+1; i++) {
    r->d[i] = a->d[i] + b->d[i];
  }
  r->top = max + 1;
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

__device__ unsigned int bn_sub_words(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b, int cl) {
  BN_ULONG t1, t2;
  int c = 0;

  do {
    t1 = a[0]; t2 = b[0];
    r[0] = (t1 - t2 -c) & BN_MASK2;
    c=(t1 < t2); a++; b++;
  } while (--cl);

  return c;
}

__device__ unsigned int bn_add_words(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b, int cl, unsigned int carry) {

  unsigned int c = carry;
  BN_ULONG l;

  do {
    BN_ULONG t = a[0];
    t += c;
    c = (t < c);
    l=(t+b[0])&BN_MASK2;
    c+=l < t;
    r[0] = l;
    a++; b++; 
  } while (--cl);

  return c;

}

__device__ void bn_mod(BIGNUM* a, BIGNUM* m, BIGNUM* r, int mlen) {
  int i;
  for (i = a->top - 1; i >= mlen; i--) {
    if (a->d[i]) {
      unsigned int carry = bn_sub_words(r->d, a->d, m->d, mlen);
      carry = bn_add_words(r->d, r->d, m->d, mlen, carry);
    }
    else
      r->d[i] = 0;
  }
  for (; i >= 0; i--)
    r->d[i] = a->d[i];
  r->top = mlen;
}

__global__ void testKernel() {

  BN_ULONG a_d[10];
  BN_ULONG b_d[10]; 
  BN_ULONG c_d[20];
  BN_ULONG m_d[10];

  BIGNUM a;
  BIGNUM b;
  BIGNUM c;
  BIGNUM m;

  // Initialize a and b
  /*a_d[0] = 0x0000000a; 
  a.d = a_d; a.top = 1;
  b_d[0] = 0x0000000b;
  b.d = b_d; b.top = 1;*/
  a.d = a_d; 
  a.top = 1; 
  a.d[0] = 10;
  b.d = b_d;
  b.top = 1;
  b.d[0] = 20;

  // Print inputs
  bn_print("A: ", &a);
  bn_print("B: ", &b);

  // Addition
  c.d = c_d;
  bn_add(&a, &b, &c);

  // Print result  
  bn_print("A + B: ", &c);

  // Modulus  
  m.d = m_d; m.top = 1;
  m_d[0] = 0x00000064;

  bn_mod(&c, &m, &c, 1);
  
  // Print result
  bn_print("C mod M: ", &c);
}
