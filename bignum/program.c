#include <openssl/bn.h>
#include <stdio.h>

// Print BIGNUM in hexadecimal
void print_bn(char* msg, BIGNUM* a) {
  char* str = BN_bn2hex(a);
  printf("%s %s\n", msg, str);
  OPENSSL_free(str); 
}

int main() {
  BN_CTX *ctx = BN_CTX_new();
  
  // Addition
  BIGNUM *a = BN_new();
  BIGNUM *b = BN_new();
  BIGNUM *c = BN_new();

  // Initialize a and b
  BN_dec2bn(&a, "70");
  BN_dec2bn(&b, "50");
  
  // Print inputs
  print_bn("A:", a);
  print_bn("B:", b);

  // Add A and B
  BN_add(c, a, b);

  // Print A + B
  print_bn("A + B:", c);

  // Modular Reduction
  BIGNUM *m = BN_new();
  BN_dec2bn(&m, "100");

  // Print M
  print_bn("M:", m);
  
  BN_mod(c, c, m, ctx);

  // Print C mod M
  print_bn("C mod M:", c);

  // Other operations like subtraction, multiply, divide etc.

  BN_free(a);
  BN_free(b);
  BN_free(c);
  BN_free(m);

  BN_CTX_free(ctx);
}