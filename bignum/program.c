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
  // BN_dec2bn(&a, "70");
  // BN_dec2bn(&b, "50");
  BN_hex2bn(&a, "C17747B1566D9FE8AB7087E3F0C50175B788A1C84F4C756C405000A0CA2248E1");
  BN_hex2bn(&b, "6C91CEA9CF0CAC55A7596D16B56D2AEFD204BB99DD677993158A7E6564F93CDF");
  
  // Print inputs
  print_bn("A:", a);
  print_bn("B:", b);

  // Add A and B
  BN_add(c, a, b);

  // Print A + B
  print_bn("A + B:", c);

  // Modular Reduction
  // old ++
  BIGNUM *m = BN_new();
  BN_dec2bn(&m, "100");
  // Print M
  print_bn("M:", m);  
  BN_mod(c, c, m, ctx);
  // Print C mod M
  print_bn("C mod M:", c);
  // old --

  // new ++
  /*BIGNUM *curveOrder = BN_new();
  // Set curve order for secp256k1
	BN_dec2bn(&curveOrder, "115792089237316195423570985008687907852837564279074904382605163141518161494337");
  print_bn_hex("Curve Order", curveOrder);
  // Convert byte arrays to big numbers
	BN_bin2bn(il, 32, a);
	BN_bin2bn(key, 32, parentKeyInt);
  BN_mod_add(newKey, a, parentKeyInt, curveOrder, ctx);*/
  // new ++


  BN_free(a);
  BN_free(b);
  BN_free(c);
  BN_free(m);

  BN_CTX_free(ctx);
}