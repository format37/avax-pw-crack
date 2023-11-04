#include "bn.h"
#include <stdio.h>
#include <string.h>
#include "ec.h"
#include "obj_mac.h"


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

// Function to compress public key
void compress_pubkey(EC_KEY *key, unsigned char *compressed, size_t *compressed_len) {
    const EC_POINT *point = EC_KEY_get0_public_key(key);
    const EC_GROUP *group = EC_KEY_get0_group(key);
    *compressed_len = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, compressed, 65, NULL);
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



  // Derive the public key
  EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
  BIGNUM *priv_key = BN_new();
  unsigned char compressed_pubkey[65];
  size_t compressed_pubkey_len;

  // Set private key
  // BN_hex2bn(&priv_key, "2E09165B257A4C3E52C9F4FAA6322C66CEDE807B7D6B4EC3960820795EE5447F");
  BN_bin2bn(newKeyBytes, newKeyLen, priv_key);
  EC_KEY_set_private_key(eckey, priv_key);

  // Generate public key
  EC_POINT *pub_key = EC_POINT_new(EC_KEY_get0_group(eckey));
  EC_POINT_mul(EC_KEY_get0_group(eckey), pub_key, priv_key, NULL, NULL, NULL);
  EC_KEY_set_public_key(eckey, pub_key);

  // Compress public key
  compress_pubkey(eckey, compressed_pubkey, &compressed_pubkey_len);

  // Print compressed public key
  printf("public: ");
  for (size_t i = 0; i < compressed_pubkey_len; i++) {
      printf("%02x", compressed_pubkey[i]);
  }
  printf("\n");

  // Cleanup
  EC_POINT_free(pub_key);
  BN_free(priv_key);
  EC_KEY_free(eckey);



  BN_free(a);
  BN_free(b);
  BN_free(newKey);
  BN_free(curveOrder);
  BN_CTX_free(ctx);
}