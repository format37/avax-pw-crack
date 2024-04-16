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
        gmp_printf("p1.x: %Zx\n", p1.x);
        gmp_printf("p1.y: %Zx\n", p1.y);
        gmp_printf("a: %Zx\n", a);
        gmp_printf("p: %Zx\n", p);
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

        gmp_printf("s: %Zx\n", s);

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

int main() {
    // Initialize constants
    init_constants();

    // Initialize point at infinity
    init_point_at_infinity();

    Point r;
    mpz_init(r.x);
    mpz_init(r.y);
    mpz_set_ui(r.x, 0);
    mpz_set_ui(r.y, 0);

    // Create point G
    Point G;
    mpz_init(G.x);
    mpz_init(G.y);
    mpz_set(G.x, Gx);
    mpz_set(G.y, Gy);

    gmp_printf("0 x: %Zx\n", G.x);
    gmp_printf("0 y: %Zx\n", G.y);
    r = point_add(r, G);
    // print the current x and y    
    gmp_printf("1 x: %Zx\n", r.x);
    gmp_printf("1 y: %Zx\n", r.y);

    return 0;
}
