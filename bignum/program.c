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

// public ++
// Point structure 
typedef struct {
  BIGNUM *x;
  BIGNUM *y;
} Point;

// Allocate memory for point
Point* point_new() {
  Point* point = malloc(sizeof(Point));
  point->x = BN_new();
  point->y = BN_new();
  return point;
}

// Free memory 
void point_free(Point* point) {
  BN_free(point->x);
  BN_free(point->y);
  free(point);
}

// Derive public key
Point* derive_public_key(BIGNUM* private_key) {

  // Constants for secp256k1
  BIGNUM *p = NULL;
  BIGNUM *a = NULL; 
  BIGNUM *b = NULL;
  BIGNUM *Gx = NULL;
  BIGNUM *Gy = NULL;

  // Initialize constants
  BN_dec2bn(&p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"); 
  BN_dec2bn(&a, "0");
  BN_dec2bn(&b, "7");
  BN_hex2bn(&Gx, "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
  BN_hex2bn(&Gy, "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
  
  BN_CTX *ctx = BN_CTX_new();
  Point* result = point_new();
  
  // result = private_key * G
  Point* current = point_new();
  // current->x = BN_dup(Gx);
  // current->y = BN_dup(Gy);
  current->x = BN_new();
  current->y = BN_new();

  // Set current to initial point
  BN_copy(current->x, Gx); 
  BN_copy(current->y, Gy);

  BIGNUM* coef = BN_dup(private_key);
  
  while(!BN_is_zero(coef)) {
    /*
    if (BN_is_odd(coef)) {
      if (BN_is_zero(result->x)) {
        BN_copy(result->x, current->x);
        BN_copy(result->y, current->y);
      } else {
        // point addition
        BIGNUM *x3, *y3, *s, *u, *v;
        x3 = BN_new();
        y3 = BN_new();
        s = BN_new();
        u = BN_new();
        v = BN_new();
        
        // u = (current->x - result->x) % p
        BN_mod_sub(u, current->x, result->x, p, ctx);
        
        // v = (current->y - result->y) % p 
        BN_mod_sub(v, current->y, result->y, p, ctx);
        
        // s = (v * pow(u, p-2, p)) % p
        BN_mod_inverse(s, u, p, ctx);
        BN_mod_mul(s, s, v, p, ctx);
        
        // x3 = (s*s - result->x - current->x) % p
        BN_mod_sqr(x3, s, p, ctx);
        BN_mod_sub(x3, x3, result->x, p, ctx);
        BN_mod_sub(x3, x3, current->x, p, ctx);
        
        // y3 = (s*(result->x - x3) - result->y) % p
        BN_mod_sub(y3, result->x, x3, p, ctx);
        BN_mod_mul(y3, s, y3, p, ctx);
        BN_mod_sub(y3, y3, result->y, p, ctx);
        
        BN_copy(result->x, x3);
        BN_copy(result->y, y3);

        BN_free(x3);
        BN_free(y3);
        BN_free(s); 
        BN_free(u);
        BN_free(v);
      }
    }*/
    
    // current = current + current
    { 
      BIGNUM *x3, *y3, *s, *u, *v;
      x3 = BN_new();
      y3 = BN_new();
      s = BN_new();
      u = BN_new();
      v = BN_new();
      /*
      // u = (current->x - current->x) % p
      BN_mod_sub(u, current->x, current->x, p, ctx);
        
      // v = (current->y - current->y) % p
      BN_mod_sub(v, current->y, current->y, p, ctx);
      
      // s = (3*(current->x)^2 + a) * pow(2*current->y, p-2, p) % p 
      BN_mod_sqr(s, current->x, p, ctx);
      // BN_mul_word(s, s, 3);
      BN_mul_word(s, 3); // multiply s by 3
      BN_add(s, s, a);
      BN_lshift1(v, current->y);
      BN_mod_inverse(v, v, p, ctx);
      BN_mod_mul(s, s, v, p, ctx);
      
      // x3 = (s*s - 2*current->x) % p
      BN_mod_sqr(x3, s, p, ctx);
      BN_lshift1(u, current->x);
      BN_mod_sub(x3, x3, u, p, ctx);
      
      // y3 = (s*(current->x - x3) - current->y) % p
      BN_mod_sub(y3, current->x, x3, p, ctx);
      BN_mod_mul(y3, s, y3, p, ctx);
      BN_mod_sub(y3, y3, current->y, p, ctx);

      BN_copy(current->x, x3);
      BN_copy(current->y, y3);

      BN_free(x3);
      BN_free(y3);
      BN_free(s);
      BN_free(u); 
      BN_free(v);*/
    }
    
    BN_rshift1(coef, coef);
  }

  point_free(current);

  BN_CTX_free(ctx);
  
  return result;
}
// public --

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

  // Public Key
  Point* public_key = derive_public_key(newKey);
  print_bn("Debug C public_key->x", public_key->x);
  print_bn_hex("Debug C public_key->x", public_key->x);
  print_bn("Debug C public_key->y", public_key->y);
  print_bn_hex("Debug C public_key->y", public_key->y);

  BN_free(a);
  BN_free(b);
  BN_free(newKey);
  BN_free(curveOrder);
  BN_CTX_free(ctx);
}