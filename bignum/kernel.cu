//#include <openssl/bn.h>
extern "C" {
	#include "bn.h"
}

#include <stdio.h>

// Print BIGNUM in hexadecimal
__device__ void print_bn(char* msg, BIGNUM* a) {
  char* str = BN_bn2hex(a);
  printf("%s %s\n", msg, str);
  OPENSSL_free(str); 
}

__global__ void testKernel() {
  BN_CTX *ctx = BN_CTX_new();
  
  // Addition
  BIGNUM *a = BN_new();
  BIGNUM *b = BN_new();
  BIGNUM *c = BN_new();

  BN_dec2bn(&a, "10");
  BN_dec2bn(&b, "20");

  print_bn("A:", a);
  print_bn("B:", b);

  BN_add(c, a, b);

  print_bn("A + B:", c);

  // Modular Reduction
  BIGNUM *m = BN_new();
  BN_dec2bn(&m, "100");
  
  BN_mod(c, c, m, ctx);

  print_bn("C mod M:", c);

  // Other operations like subtraction, multiply, divide etc.

  BN_free(a);
  BN_free(b);
  BN_free(c);
  BN_free(m);

  BN_CTX_free(ctx);
}
