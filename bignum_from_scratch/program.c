#include <openssl/bn.h>
#include <stdio.h>

void print_as_hex_char(unsigned char *data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Debug print for OpenSSL BIGNUM
void print_bn(const char* label, const BIGNUM* bn) {
	char* bn_str = BN_bn2dec(bn);
	printf("%s: %s\n", label, bn_str);
	OPENSSL_free(bn_str);
}

// Debug print for OpenSSL BIGNUM in Hexadecimal
void print_bn_hex(const char* label, const BIGNUM* bn) {
    char* bn_str = BN_bn2hex(bn);
    printf("%s (Hexadecimal): %s\n", label, bn_str);
    OPENSSL_free(bn_str);
}

int main() {  
  // Addition
  BIGNUM *a = BN_new();
  BIGNUM *b = BN_new(); // parentKeyInt
  BIGNUM *curveOrder = BN_new();
  BIGNUM *newKey = BN_new();
  BN_CTX *ctx = BN_CTX_new();

  // Set curve order for secp256k1
	BN_dec2bn(&curveOrder, "115792089237316195423570985008687907852837564279074904382605163141518161494337");
  print_bn("Curve Order", curveOrder);
  print_bn_hex("Curve Order", curveOrder); 

  // Initialize a and b
  BN_hex2bn(&a, "C17747B1566D9FE8AB7087E3F0C50175B788A1C84F4C756C405000A0CA2248E1");
  BN_hex2bn(&b, "6C91CEA9CF0CAC55A7596D16B56D2AEFD204BB99DD677993158A7E6564F93CDF");
  
  // Print inputs
  print_bn("program C a (Before mod_add)", a);
  print_bn_hex("program C a (Before mod_add)", a);
  print_bn("program C parentKeyInt (Before mod_add)", b);
  print_bn_hex("program C parentKeyInt (Before mod_add)", b);

  // Debug ++ TODO: Remove
	BIGNUM *tempSum = BN_new();
  BN_add(tempSum, a, b);
  unsigned char my_buffer[64];
	
  BN_bn2bin(tempSum, my_buffer);

  printf("Debug C Intermediate Sums (Hexadecimal):\n");
  for (int i = 0; i < BN_num_bytes(tempSum); i+=4) {
      uint32_t val = *((uint32_t*)(&my_buffer[i]));
      printf("At index %d: val = %x\n", i / 4, val);
  }
  // Debug --

  BN_add(newKey, a, b);
  print_bn("Debug C newKey (After add)", newKey);
  print_bn_hex("Debug C newKey (After add)", newKey);
  
  BN_nnmod(newKey, newKey, curveOrder, ctx);
	print_bn("Debug C newKey (After mod)", newKey);
  print_bn_hex("Debug C newKey (After mod)", newKey);

  uint8_t newKeyBytes[32] = {0};  // Initialize to zero
  int newKeyLen = 0;
  newKeyLen = BN_bn2bin(newKey, newKeyBytes);
  printf("private: ");
	print_as_hex_char(newKeyBytes, newKeyLen);

  BN_free(a);
  BN_free(b);
  BN_free(newKey);
  BN_free(curveOrder);
  BN_CTX_free(ctx);
}