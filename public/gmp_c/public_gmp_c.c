#include <gmp.h>
#include <stdlib.h>
#include <stdio.h>

mpz_t p, a, b, Gx, Gy; // Constants for secp256k1

// Point structure
typedef struct {
  mpz_t x;
  mpz_t y;
} Point;

Point POINT_AT_INFINITY;

void init_point_at_infinity() {
  mpz_init_set_ui(POINT_AT_INFINITY.x, 0);
  mpz_init_set_ui(POINT_AT_INFINITY.y, 0); 
}

// Initialize your constants in a function
void init_constants() {
    mpz_init_set_str(p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    mpz_init_set_ui(a, 0);
    mpz_init_set_ui(b, 7);
    mpz_init_set_str(Gx, "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
    mpz_init_set_str(Gy, "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
}

// Point addition
Point point_add(Point p1, Point p2) {
    /*if (mpz_cmp(p1.a, p2.a) != 0 || mpz_cmp(p1.b, p2.b) != 0) {
        printf("Points are not on the same curve\n");
    }*/ // Not needed for secp256k1
    printf("++ point_add ++\n");
    gmp_printf(">> p1.x: %Zx\n", p1.x);
    gmp_printf(">> p1.y: %Zx\n", p1.y);
    gmp_printf(">> p2.x: %Zx\n", p2.x);
    gmp_printf(">> p2.y: %Zx\n", p2.y);

    Point result;
    mpz_init(result.x);
    mpz_init(result.y);

    mpz_t s, x3, y3, tmp1, tmp2;
    mpz_inits(s, x3, y3, tmp1, tmp2, NULL);

    // Handle point at infinity
    if (mpz_cmp_ui(p1.x, 0) == 0) {
        printf("p1 point at infinity\n");
        // p1 is point at infinity
        return p2;
    }
    //if (mpz_cmp_ui(p2.x, 0) == 0 && mpz_cmp_ui(p2.y, 0) == 0) {
    if (mpz_cmp_ui(p2.x, 0) == 0) {
        printf("p2 point at infinity\n");
        // p2 is point at infinity
        return p1;
    }

    // Case 1: p1.x == p2.x && p1.y != p2.y
    if (mpz_cmp(p1.x, p2.x) == 0 && mpz_cmp(p1.y, p2.y) != 0) {
        printf("p1.x == p2.x && p1.y != p2.y\n");
        return POINT_AT_INFINITY;
    }

    // Case 2: self.x != other.x
    if (mpz_cmp(p1.x, p2.x) != 0) {
        printf("p1.x != p2.x\n");

        // Full point addition formula
        mpz_sub(tmp1, p2.y, p1.y); 
        mpz_sub(tmp2, p2.x, p1.x);
        mpz_mod(tmp1, tmp1, p);
        mpz_mod(tmp2, tmp2, p);
        mpz_invert(tmp2, tmp2, p); 
        mpz_mul(s, tmp1, tmp2);
        mpz_mod(s, s, p);

        mpz_pow_ui(x3, s, 2);
        mpz_sub(x3, x3, p1.x);
        mpz_sub(x3, x3, p2.x);
        mpz_mod(x3, x3, p);

        mpz_sub(tmp1, p1.x, x3);
        mpz_mul(y3, s, tmp1);
        mpz_sub(y3, y3, p1.y);  
        mpz_mod(y3, y3, p);
    } else {
        // Case 3: p1.x == p2.x
        gmp_printf("p1.x == p2.x\n");
        // gmp_printf("p1.x: %Zx\n", p1.x);
        // gmp_printf("p1.y: %Zx\n", p1.y);
        // gmp_printf("a: %Zx\n", a);
        // gmp_printf("p: %Zx\n", p);
        // Point doubling formula
        mpz_pow_ui(tmp1, p1.x, 2); // tmp1 = p1.x^2  
        mpz_mul_ui(tmp1, tmp1, 3); // tmp1 = 3 * p1.x^2
        mpz_add(tmp1, tmp1, a);
        mpz_mod(tmp1, tmp1, p);

        mpz_mul_ui(tmp2, p1.y, 2);
        mpz_mod(tmp2, tmp2, p);
        mpz_invert(tmp2, tmp2, p);  

        mpz_mul(s, tmp1, tmp2);
        mpz_mod(s, s, p);

        // gmp_printf("s: %Zx\n", s);

        mpz_pow_ui(x3, s, 2);
        mpz_sub(x3, x3, p1.x);
        mpz_sub(x3, x3, p1.x);
        mpz_mod(x3, x3, p);

        mpz_sub(tmp1, p1.x, x3);
        mpz_mul(y3, s, tmp1);
        mpz_sub(y3, y3, p1.y);
        mpz_mod(y3, y3, p);
    }

    mpz_set(result.x, x3);
    mpz_set(result.y, y3);
    
    // Free the temporary variables
    mpz_clears(s, x3, y3, tmp1, tmp2, NULL);

    return result;
}

// Scalar point multiplication 
Point point_multiply(Point p, mpz_t n) {
  printf("++ point_multiply ++\n");
  // int debug_counter = 0;
  Point r;
  mpz_init(r.x);
  mpz_init(r.y);
  mpz_set_ui(r.x, 0);
  mpz_set_ui(r.y, 0);
  
  Point pp = p;
  mpz_t temp;
  mpz_init(temp);

  // print p
  gmp_printf(">> point.x: %Zx\n", p.x);
  gmp_printf(">> point.y: %Zx\n", p.y);
  // print n
  gmp_printf(">> n scalar: %Zx\n", n);
  
  unsigned int current_step = 0;

  while (mpz_cmp_ui(n, 0) > 0) {
    printf("\n### Step: %d\n", current_step);
    // print the current x and y
    // gmp_printf("0 x: %Zx\n", pp.x);
    // gmp_printf("0 y: %Zx\n", pp.y);
    mpz_mod_ui(temp, n, 2);
    // print pre_point_add r and pp
    gmp_printf(">> pp.x: %Zx\n", pp.x);
    gmp_printf(">> pp.y: %Zx\n", pp.y);
    if (mpz_cmp_ui(temp, 1) == 0) {
      gmp_printf("\n[0]\n");
      gmp_printf(">> point_add r.x: %Zx\n", r.x);
      gmp_printf(">> point_add r.y: %Zx\n", r.y);
      gmp_printf(">> point_add pp.x: %Zx\n", pp.x);
      gmp_printf(">> point_add pp.y: %Zx\n", pp.y);
      r = point_add(r, pp);
      gmp_printf("<< point_add r.x: %Zx\n", r.x);
      gmp_printf("<< point_add r.y: %Zx\n\n", r.y);
    }
    gmp_printf("\n[1]\n");
    gmp_printf(">> point_add pp.x: %Zx\n", pp.x);
    gmp_printf(">> point_add pp.y: %Zx\n", pp.y);
    pp = point_add(pp, pp);    
    gmp_printf("<< point_add pp.x: %Zx\n", pp.x);
    gmp_printf("<< point_add pp.y: %Zx\n", pp.y);
    mpz_tdiv_q_ui(n, n, 2);
    // print the current x and y
    // gmp_printf("2 x: %Zx\n", pp.x);
    // gmp_printf("2 y: %Zx\n", pp.y);
    // debug_counter++;
    /*if (debug_counter > 1) {
      gmp_printf("3 x: %Zx\n", r.x);
      gmp_printf("3 y: %Zx\n", r.y);
      exit(0);
    }*/
    // gmp_printf("3 x: %Zx\n", r.x);
    // gmp_printf("3 y: %Zx\n", r.y);
    current_step++;
  }

  mpz_clear(temp);
  printf("-- point_multiply --\n");
  return r;
}

// Derive public key
Point derive_public_key(mpz_t private_key) {
  // Create point G
  Point G;
  mpz_init(G.x);
  mpz_init(G.y);
  mpz_set(G.x, Gx);
  mpz_set(G.y, Gy);

  // Derive public key 
  Point public_key = point_multiply(G, private_key);

  return public_key;
}

// Compress public key  
char* compress_public_key(Point public_key) {

  mpz_t mod_result;
  mpz_init(mod_result);

  // Calculate public_key.y % 2
  mpz_mod_ui(mod_result, public_key.y, 2);
  // char prefix = (mpz_cmp_ui(mod_result, 0) == 0) ? '0' : '1';
  char prefix = (mpz_cmp_ui(mod_result, 0) == 0) ? '02' : '03';

  // Convert x coordinate to hexadecimal string
  char *x_str = mpz_get_str(NULL, 16, public_key.x);

  // Make sure it's 64 characters long, zero-padded if necessary
  char padded_x_str[65];
  snprintf(padded_x_str, sizeof(padded_x_str), "%064s", x_str);

  // Concatenate the prefix and the x coordinate
  char *compressed = malloc(65 + 1);  // 65 for the key and 1 for null-terminator
  sprintf(compressed, "%c%s", prefix, padded_x_str);

  // Clean up
  mpz_clear(mod_result);
  free(x_str);

  return compressed;
}

int main() {

  // Initialize constants
  init_constants();

  // Initialize point at infinity
  init_point_at_infinity();

  // Initialize and set private key
  mpz_t private_key;
  mpz_init(private_key);
  mpz_set_str(private_key, "2E09165B257A4C3E52C9F4FAA6322C66CEDE807B7D6B4EC3960820795EE5447F", 16);

  // Print private key
  gmp_printf("Private Key: %Zx\n", private_key);

  // Derive public key
  Point public_key = derive_public_key(private_key);

  // Print public key
  gmp_printf("Public Key (x, y): (%Zx, %Zx)\n", public_key.x, public_key.y);

  // Compress public key
  char* compressed = compress_public_key(public_key);  // Make sure to adapt this function to use GMP as well
  printf("Compressed public key: %s\n", compressed);

  // Cleanup
  free(compressed);
  mpz_clear(private_key);
  mpz_clear(p);
  mpz_clear(a);
  mpz_clear(b);
  mpz_clear(Gx);
  mpz_clear(Gy);
  
  return 0;
}
