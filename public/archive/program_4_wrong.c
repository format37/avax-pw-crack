#include <stdio.h>  
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

// Constants for secp256k1
const uint64_t p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F; 
const uint64_t a = 0;
const uint64_t b = 7;
const uint64_t Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
const uint64_t Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

// Point structure 
typedef struct {
  uint64_t x;
  uint64_t y;
} Point;

// Forward declarations
uint64_t mod_inverse(uint64_t a, uint64_t n); 
Point derive_public_key(uint64_t private_key);

// Modular inverse
uint64_t mod_inverse(uint64_t a, uint64_t n) {
  uint64_t t, newt;
  uint64_t r = n;
  uint64_t newr = a;
  uint64_t q;
  uint64_t m = 0;
  uint64_t m_old = 1;

  while (newr != 0) {
    q = r/newr;

    t = newt; 
    newt = m - q*newt;
    m = t;

    t = newr;
    newr = r - q*newr;
    r = t;
  }

  if (r > 1) return 0;
  if (m < 0) m += n;

  return m;
}

// Point addition
Point point_add(Point p1, Point p2) {
  
  // Handle point at infinity
  if (p1.x == 0 && p1.y == 0) {
    return p2;
  }
  if (p2.x == 0 && p2.y == 0) {
    return p1; 
  }

  // Case 1: p1 == p2
  if (p1.x == p2.x && p1.y == p2.y) {
    uint64_t s = (3*p1.x*p1.x + a) * mod_inverse(2*p1.y, p) % p;
    uint64_t x3 = (s*s - 2*p1.x) % p;  
    uint64_t y3 = (s*(p1.x - x3) - p1.y) % p;
    Point p3 = {x3, y3};
    return p3;
  }

  // Case 2: p1 != p2
  uint64_t s = (p2.y - p1.y) * mod_inverse(p2.x - p1.x, p) % p;
  uint64_t x3 = (s*s - p1.x - p2.x) % p;
  uint64_t y3 = (s*(p1.x - x3) - p1.y) % p;
  Point p3 = {x3, y3};

  return p3;
}

// Scalar point multiplication 
Point point_multiply(Point p, uint64_t n) {
  
  Point r = {0, 0}; 
  Point pp = p;

  while (n > 0) {
    if (n & 1) {
      r = point_add(r, pp);  
    }
    pp = point_add(pp, pp);
    n >>= 1;
  }

  return r;
}

// Derive public key
Point derive_public_key(uint64_t private_key) {
  // Create point G
  Point G;
  G.x = Gx;
  G.y = Gy;
  // Point public_key = point_multiply(point_multiply(Gx, Gy), private_key);
  // Derive public key 
  Point public_key = point_multiply(G, private_key);
  return public_key;
}

// Compress public key  
char* compress_public_key(Point public_key) {

  char prefix = (public_key.y % 2 == 0) ? '0' : '1';
  char x_str[65];
  sprintf(x_str, "%0.64X", public_key.x);
  
  char* compressed = malloc(65);
  sprintf(compressed, "%c%s", prefix, x_str);

  return compressed;
}

int main() {

  // Private key 
  uint64_t private_key = 0x2e09165b257a4c3e52c9f4faa6322c66cede807b7d6b4ec3960820795ee5447f;

  // Derive public key
  Point public_key = derive_public_key(private_key);

  // Print public key
  printf("Public Key (x, y): (%0.64lX, %0.64lX)\n", public_key.x, public_key.y);

  // Compress public key
  char* compressed = compress_public_key(public_key);
  printf("Compressed public key: %s\n", compressed);

  free(compressed);
  
  return 0;
}