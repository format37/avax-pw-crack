#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>

// Constants for secp256k1 
static const BIGNUM *p;
static const BIGNUM *Gx;
static const BIGNUM *Gy;
p = BN_new();
Gx = BN_new();
Gy = BN_new();
BN_hex2bn(&p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"); 
BN_hex2bn(&Gx, "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
BN_hex2bn(&Gy, "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
// const BN_ULONG p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
const BN_ULONG a = 0;
const BN_ULONG b = 7;
// const BN_ULONG Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
// const BN_ULONG Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

// Structure to represent a point
typedef struct {
  BIGNUM *x;  
  BIGNUM *y;
} EC_POINT;

// Compress public key 
void compressPubKey(EC_POINT *pubKey, unsigned char *comp) {
    //
}

// Point addition
EC_POINT* pointAdd(EC_POINT *p1, EC_POINT *p2) {

  BN_CTX *ctx = BN_CTX_new();

  BIGNUM *lambda = BN_new();
  BIGNUM *x3 = BN_new();
  BIGNUM *y3 = BN_new();

  // lambda = (p2.y - p1.y) / (p2.x - p1.x) mod p
  BN_mod_sub(lambda, p2->y, p1->y, p, ctx);
  BN_mod_sub(x3, p2->x, p1->x, p, ctx);
  BN_mod_inverse(x3, x3, p, ctx); 
  BN_mod_mul(lambda, lambda, x3, p, ctx);

  // x3 = lambda^2 - p1.x - p2.x mod p
  BN_mod_sqr(x3, lambda, p, ctx);
  BN_mod_sub(x3, x3, p1->x, p, ctx);
  BN_mod_sub(x3, x3, p2->x, p, ctx);

  // y3 = lambda(p1.x - x3) - p1.y mod p
  BN_mod_sub(y3, p1->x, x3, p, ctx);
  BN_mod_mul(y3, lambda, y3, p, ctx);
  BN_mod_sub(y3, y3, p1->y, p, ctx);

  EC_POINT *res = malloc(sizeof(EC_POINT));
  res->x = x3;
  res->y = y3;

  BN_CTX_free(ctx);

  return res;
}

EC_POINT* pointDouble(EC_POINT *p) {

  BN_CTX *ctx = BN_CTX_new();

  BIGNUM *lambda = BN_new();
  BIGNUM *x3 = BN_new(); 
  BIGNUM *y3 = BN_new();

  // Initialize BIGNUM p
  //BIGNUM *p = BN_new();
  //BN_hex2bn(&p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");

  // lambda = (3*p->x^2 + a) / (2*p->y) mod p
  BN_mod_sqr(x3, p->x, p, ctx);
  BN_mod_add(x3, x3, x3, p, ctx);
  BN_mod_add(x3, x3, p->x, p, ctx);
  BN_add(y3, p->y, p->y);
  BN_mod_inverse(y3, y3, p, ctx);
  BN_mod_mul(lambda, x3, y3, p, ctx);

  // x3 = lambda^2 - 2*p->x mod p  
  BN_mod_sqr(x3, lambda, p, ctx);
  BN_mod_lshift1(y3, p->x, p, ctx);
  BN_mod_sub(x3, x3, y3, p, ctx);

  // y3 = lambda(p->x - x3) - p->y mod p
  BN_mod_sub(y3, p->x, x3, p, ctx);
  BN_mod_mul(y3, y3, lambda, p, ctx);
  BN_mod_sub(y3, y3, p->y, p, ctx);

  EC_POINT *res = malloc(sizeof(EC_POINT));
  res->x = x3;
  res->y = y3;

  BN_CTX_free(ctx);

  return res;
}

// Point multiplication
EC_POINT* pointMul(BIGNUM *d, EC_POINT *p) {

  EC_POINT *result = malloc(sizeof(EC_POINT)); // Initialize to infinity
  result->x = NULL;
  result->y = NULL;

  EC_POINT *temp = malloc(sizeof(EC_POINT));
  temp->x = BN_new();
  temp->y = BN_new();

  int i = 0;
  BIGNUM *coeff = BN_new();

  BN_copy(coeff, d);

  while (!BN_is_zero(coeff)) {
    
    if (BN_is_odd(coeff)) {
      if (i == 0) {
        BN_copy(result->x, p->x);
        BN_copy(result->y, p->y);  
      } else {
        pointAdd(result, temp); // result = result + temp
      }
    }

    pointDouble(temp); // temp = 2 * temp
    BN_rshift1(coeff, coeff);
    i++;
  }
    
  // Free memory
  BN_free(coeff);
  BN_free(temp->x);
  BN_free(temp->y);
  free(temp);


  return result;
}

int main() {
    BIGNUM *privKey = BN_new(); //+
    EC_POINT *pubKey = malloc(sizeof(EC_POINT)); //+
    // Initialize pubKey x and y
    pubKey->x = BN_new(); //+
    pubKey->y = BN_new(); //+
    // Set pubKey x and y
    BN_hex2bn(&pubKey->x, "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"); //+
    BN_hex2bn(&pubKey->y, "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"); //+

    // Set private key
    BN_hex2bn(&privKey, "2E09165B257A4C3E52C9F4FAA6322C66CEDE807B7D6B4EC3960820795EE5447F"); //+

    // Derive public key
    pubKey = pointMul(privKey, pubKey);

    // Compress public key
    unsigned char compressed[65]; 
    compressPubKey(pubKey, compressed);

    return 0;
}
