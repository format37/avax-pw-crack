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
    //mpz_init_set_str(p, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);    
    mpz_init_set_ui(a, 0);
    mpz_init_set_ui(b, 7);
    // mpz_init_set_str(Gx, "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
    // mpz_init_set_str(Gy, "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
    mpz_init_set_str(Gx, "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5", 16);
    mpz_init_set_str(Gy, "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a", 16);
}

// Point addition
Point point_add(Point p1, Point p2) {
    printf("++ point_add ++\n");
    gmp_printf(">> p1.x: %Zx\n", p1.x);
    gmp_printf(">> p1.y: %Zx\n", p1.y);
    gmp_printf(">> p2.x: %Zx\n", p2.x);
    gmp_printf(">> p2.y: %Zx\n", p2.y);
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
        gmp_printf("[a] << mpz_sub tmp1: %Zx\n", tmp1);
        mpz_sub(tmp2, p2.x, p1.x);
        gmp_printf("[c] >> mpz_mod tmp1: %Zx\n", tmp1);
        gmp_printf("[c] >> mpz_mod p: %Zx\n", p);        
        mpz_mod(tmp1, tmp1, p);
        gmp_printf("[c] << mpz_mod tmp1: %Zx\n", tmp1);
        
        gmp_printf("[d] >> mpz_mod tmp2: %Zx\n", tmp2);
        gmp_printf("[d] >> mpz_mod p: %Zx\n", p);
        mpz_mod(tmp2, tmp2, p);
        gmp_printf("[d] << mpz_mod tmp2: %Zx\n", tmp2);

        // print tmp2 and p
        gmp_printf("\n[0] >> mpz_invert tmp2: %Zx\n", tmp2);
        gmp_printf("[0] >> mpz_invert p: %Zx\n", p);
        mpz_invert(tmp2, tmp2, p);
        // print tmp2
        gmp_printf("\n[1] << mpz_invert tmp2: %Zx\n", tmp2);
        gmp_printf("[1] << mpz_invert p: %Zx\n", p);
        
        gmp_printf("\n[2] >> mpz_mul s: %Zx\n", s);
        gmp_printf("[2] >> mpz_mul tmp1: %Zx\n", tmp1);
        gmp_printf("[2] >> mpz_mul tmp2: %Zx\n", tmp2);
        mpz_mul(s, tmp1, tmp2);
        gmp_printf("[2] << mpz_mul s: %Zx\n", s);
        gmp_printf("[2] << mpz_mul tmp1: %Zx\n", tmp1);
        gmp_printf("[2] << mpz_mul tmp2: %Zx\n", tmp2);

        gmp_printf("\n[3] >> mpz_mod s: %Zx\n", s);
        gmp_printf("[3] >> mpz_mod p: %Zx\n", p);
        mpz_mod(s, s, p);
        gmp_printf("[3] << mpz_mod s: %Zx\n", s);

        gmp_printf("\n[4] >> mpz_pow_ui x3: %Zx\n", x3);
        gmp_printf("[4] >> mpz_pow_ui s: %Zx\n", s);
        gmp_printf("[4] >> mpz_pow_ui pow: 2\n");
        mpz_pow_ui(x3, s, 2);
        gmp_printf("[4] << mpz_pow_ui x3: %Zx\n", x3);
        gmp_printf("[4] << mpz_pow_ui s: %Zx\n", s);
        
        gmp_printf("\n[5] >> mpz_sub x3: %Zx\n", x3);
        gmp_printf("[5] >> mpz_sub p1.x: %Zx\n", p1.x);
        mpz_sub(x3, x3, p1.x);
        gmp_printf("[5] << mpz_sub x3: %Zx\n", x3);

        mpz_sub(x3, x3, p2.x);
        gmp_printf("\n[6] << mpz_sub x3: %Zx\n", x3);

        gmp_printf("\n[7] >> mpz_mod x3: %Zx\n", x3);
        gmp_printf("[7] >> mpz_mod p: %Zx\n", p);
        mpz_mod(x3, x3, p);
        gmp_printf("[7] << mpz_mod x3: %Zx\n", x3);

        mpz_sub(tmp1, p1.x, x3);
        gmp_printf("\n[8] << mpz_sub tmp1: %Zx\n", tmp1);
        
        mpz_mul(y3, s, tmp1);
        gmp_printf("\n[9] << mpz_mul y3: %Zx\n", y3);

        mpz_sub(y3, y3, p1.y);  
        gmp_printf("\n[10] << mpz_sub y3: %Zx\n", y3);

        mpz_mod(y3, y3, p);
        gmp_printf("\n[11] << mpz_mod y3: %Zx\n", y3);
    } else {
        // Case 3: p1.x == p2.x
        gmp_printf("p1.x == p2.x\n");
        gmp_printf("p1.x: %Zx\n", p1.x);
        gmp_printf("p1.y: %Zx\n", p1.y);
        gmp_printf("a: %Zx\n", a);
        gmp_printf("p: %Zx\n", p);
        
        // Point doubling formula
        gmp_printf("\n[0] >> mpz_pow_ui p1.x: %Zx\n", p1.x);
        mpz_pow_ui(tmp1, p1.x, 2); // tmp1 = p1.x^2  
        gmp_printf("\n[0] << mpz_pow_ui tmp1: %Zx\n", tmp1);
        
        mpz_mul_ui(tmp1, tmp1, 3); // tmp1 = 3 * p1.x^2
        gmp_printf("[1] << mpz_mul_ui tmp1: %Zx\n", tmp1);
        
        mpz_add(tmp1, tmp1, a); // a is zero for secp256k1
        gmp_printf("[2] << mpz_add tmp1: %Zx\n", tmp1);

        gmp_printf("\n[3] >> mpz_mod tmp1: %Zx\n", tmp1);
        gmp_printf("[3] >> mpz_mod p: %Zx\n", p);
        mpz_mod(tmp1, tmp1, p);
        gmp_printf("[3] << mpz_mod tmp1: %Zx\n", tmp1);

        mpz_mul_ui(tmp2, p1.y, 2);
        gmp_printf("\n[4] << mpz_mul_ui tmp2: %Zx\n", tmp2);

        mpz_mod(tmp2, tmp2, p);
        gmp_printf("[5] << mpz_mod tmp2: %Zx\n", tmp2);

        gmp_printf("\n[6] >> mpz_invert tmp2: %Zx\n", tmp2);
        gmp_printf("[6] >> mpz_invert p: %Zx\n", p);
        mpz_invert(tmp2, tmp2, p);  
        gmp_printf("[6] << mpz_invert tmp2: %Zx\n", tmp2);

        gmp_printf("\n[7] >> mpz_mul tmp1: %Zx\n", tmp1);
        gmp_printf("[7] >> mpz_mul tmp2: %Zx\n", tmp2);
        mpz_mul(s, tmp1, tmp2);
        gmp_printf("[7] << mpz_mul s: %Zx\n", s);
        
        mpz_mod(s, s, p);
        gmp_printf("[8] << mpz_mod s: %Zx\n", s);

        mpz_pow_ui(x3, s, 2);
        gmp_printf("[9] << mpz_pow_ui x3: %Zx\n", x3);

        mpz_sub(x3, x3, p1.x);
        gmp_printf("[10] << mpz_sub x3: %Zx\n", x3);
        mpz_sub(x3, x3, p1.x);
        gmp_printf("[11] << mpz_sub x3: %Zx\n", x3);
        mpz_mod(x3, x3, p);
        gmp_printf("[12] << mpz_mod x3: %Zx\n", x3);

        
        gmp_printf("\n[13] >> mpz_sub p1.x: %Zx\n", p1.x);
        gmp_printf("[13] >> mpz_sub x3: %Zx\n", x3);
        mpz_sub(tmp1, p1.x, x3);
        gmp_printf("[13] << mpz_sub tmp1: %Zx\n", tmp1);

        mpz_mul(y3, s, tmp1);
        gmp_printf("\n[14] << mpz_mul y3: %Zx\n", y3);
        
        gmp_printf("[15] >> mpz_sub y3: %Zx\n", y3);
        gmp_printf("[15] >> mpz_sub p1.y: %Zx\n", p1.y);
        mpz_sub(y3, y3, p1.y);
        gmp_printf("[15] << mpz_sub y3: %Zx\n", y3);
        
        mpz_mod(y3, y3, p);
        gmp_printf("[16] << mpz_mod y3: %Zx\n", y3);
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

    // Create point p2: C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5
    Point p2;
    mpz_init(p2.x);
    mpz_init(p2.y);
    mpz_set_str(p2.x, "C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5", 16);
    mpz_set_str(p2.y, "1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A", 16);
    // mpz_set_str(p2.x, "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16);
    // mpz_set_str(p2.y, "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16);
    
    // print G
    gmp_printf(">> G x: %Zx\n", G.x);
    gmp_printf(">> G y: %Zx\n", G.y);

    gmp_printf(">> p2 x: %Zx\n", p2.x);
    gmp_printf(">> p2 y: %Zx\n", p2.y);
    r = point_add(G, p2); // point addition: p1.x != p2.x
    //r = point_add(G, G); // point doubling: p1.x == p2.x
    // print the current x and y
    gmp_printf("<< r x: %Zx\n", r.x);
    gmp_printf("<< r y: %Zx\n", r.y);

    return 0;
}
