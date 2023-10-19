
#include <stdio.h>
#include <stdint.h>
#include <string.h>

// Modulo p for secp256k1
const uint8_t p[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F};

// Global constant
uint8_t three[32] = {3}; 

// Point on the elliptic curve
typedef struct {
    uint8_t x[32];
    uint8_t y[32];
} Point;

void field_inv_mod_p(uint8_t *inverse, const uint8_t *num) {
  uint8_t q, r, r1, r2, t, t1, t2;
  // uint8_t r1[32], r2[32], t1[32], t2[32]; 
  
  // Extended Euclidean algorithm
  r1 = p; 
  r2 = num;
  t1 = 0;
  t2 = 1;

  while (r2 != 0) {
    q = r1 / r2;
    
    r = r1 - q * r2;
    r1 = r2;
    r2 = r;
    
    t = t1 - q * t2;
    t1 = t2; 
    t2 = t;
  }

  if (r1 != 1) {
    // Inversion failed
    memset(inverse, 0, 32); 
  } else {
    // Make sure inverse is positive
    if (t1 < 0) {
      t1 = p - t1; 
    }

    memcpy(inverse, t1, 32);
  }
}

// Simplified 256-bit modulo p operation
void mod256(uint8_t *result) {
    // Assuming result is less than 2*p, so a simple subtraction is enough
    // A more complete implementation would use subtraction and conditional moves
    int borrow = 0;
    for (int i = 31; i >= 0; i--) {
        int16_t diff = result[i] - p[i] - borrow;
        borrow = (diff < 0) ? 1 : 0;
        if (borrow) {
            result[i] = diff + 256;
        } else {
            result[i] = diff;
        }
    }
    if (borrow == 0) {
        return;
    }
    // If borrow is still 1, the result was already < p, so we should add p back
    uint16_t carry = 0;
    for (int i = 31; i >= 0; i--) {
        uint16_t sum = result[i] + p[i] + carry;
        result[i] = sum & 0xFF;
        carry = sum >> 8;
    }
}

// 256-bit addition: result = (a + b) mod p
void add256(uint8_t *result, const uint8_t *a, const uint8_t *b) {
    uint16_t carry = 0;
    for (int i = 31; i >= 0; i--) {
        uint16_t sum = a[i] + b[i] + carry;
        result[i] = sum & 0xFF;
        carry = sum >> 8;
    }
    mod256(result);  // Modulo p
}

// 256-bit subtraction: result = (a - b) mod p
void sub256(uint8_t *result, const uint8_t *a, const uint8_t *b) {
    int16_t borrow = 0;
    for (int i = 31; i >= 0; i--) {
        int16_t diff = a[i] - b[i] - borrow;
        result[i] = diff & 0xFF;
        borrow = (diff < 0) ? 1 : 0;
    }
    mod256(result);  // Modulo p
}

// 256-bit multiplication: result = (a * b) mod p
void mul256(uint8_t *result, const uint8_t *a, const uint8_t *b) {
    uint16_t temp[64] = {0};  // Temporary result (512 bits = 64 bytes)

    // Schoolbook multiplication
    for (int i = 0; i < 32; i++) {
        for (int j = 0; j < 32; j++) {
            temp[i + j] += (uint16_t)a[i] * (uint16_t)b[j];
        }
    }

    // Carry propagation
    for (int i = 0; i < 63; i++) {
        temp[i + 1] += temp[i] >> 8;
        temp[i] &= 0xFF;
    }

    // Reduce to 256 bits and perform mod p
    // Copy lower 256 bits to result
    for (int i = 0; i < 32; i++) {
        result[i] = (uint8_t)temp[i];
    }
    // Modulo p operation (simplified for this example)
    mod256(result);
}

int points_equal(const Point *P, const Point *Q) {
    // Compare x-coordinates
    for (int i = 0; i < 32; i++) {
        if (P->x[i] != Q->x[i]) {
            return 0;  // Points are not equal
        }
    }
    // Compare y-coordinates
    for (int i = 0; i < 32; i++) {
        if (P->y[i] != Q->y[i]) {
            return 0;  // Points are not equal
        }
    }
    return 1;  // Points are equal
}

// Check if a point is at infinity
int is_point_at_infinity(const Point *P) {
    for (int i = 0; i < 32; i++) {
        if (P->x[i] != 0 || P->y[i] != 0) {
            return 0;  // Point is not at infinity
        }
    }
    return 1;  // Point is at infinity
}

// Calculate a^b mod p using the square and multiply algorithm
void pow_mod_p(uint8_t *result, const uint8_t *a, const uint8_t *b) {
    // Initialize result to 1
    memset(result, 0, 32);
    result[31] = 1;

    uint8_t base[32], exponent[32];
    memcpy(base, a, 32);
    memcpy(exponent, b, 32);

    // Loop through each bit of the exponent
    for (int i = 0; i < 256; i++) {
        uint8_t bit = (exponent[i / 8] >> (i % 8)) & 1;
        if (bit) {
            mul256(result, result, base);  // result *= base
        }
        mul256(base, base, base);  // base *= base
    }
}

// Field division: result = a / b mod p
void div_mod_p(uint8_t *result, const uint8_t *a, const uint8_t *b) {
    // Calculate b^(p-2) mod p
    uint8_t p_minus_2[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2D};
    uint8_t inverse[32];
    pow_mod_p(inverse, b, p_minus_2);

    // Calculate a * b^(p-2) mod p
    mul256(result, a, inverse);
}

// Point addition: R = P + Q
void point_add(Point *R, const Point *P, const Point *Q) {

  uint8_t lambda[32], numerator[32], denominator[32], temp[32];

  // Handle point at infinity cases
  if (is_point_at_infinity(P)) {
    *R = *Q;
    return; 
  }
  
  if (is_point_at_infinity(Q)) {
    *R = *P;
    return;
  }

  // Calculate lambda
  if (!points_equal(P, Q)) {
    // P + Q, P != Q case
    sub256(numerator, Q->y, P->y);
    sub256(denominator, Q->x, P->x); 
  } else {
    // P + P, point doubling case
    mul256(numerator, P->x, P->x); // x^2
    mul256(numerator, numerator, three); // 3*x^2
    add256(denominator, P->y, P->y); // 2*y
  }

  div_mod_p(lambda, numerator, denominator);

  // Calculate new point
  mul256(temp, lambda, lambda);
  sub256(temp, temp, P->x); // lambda^2 - x
  sub256(R->x, temp, Q->x); // lambda^2 - P.x - Q.x

  sub256(temp, P->x, R->x);
  mul256(temp, lambda, temp);
  sub256(R->y, temp, P->y);
}

// Calculate b^(p-2) mod p to find the multiplicative inverse of b
void inv_mod_p(uint8_t *inverse, const uint8_t *b) {
    uint8_t p_minus_2[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2D};
    pow_mod_p(inverse, b, p_minus_2);
}

// Point doubling: R = 2 * P
void point_double(Point *R, const Point *P) {

  uint8_t lambda[32], numerator[32], denominator[32], temp[32];

  // Handle point at infinity
  if (is_point_at_infinity(P)) {
    memset(R->x, 0, 32);
    memset(R->y, 0, 32);  
    return;
  }

  // Calculate lambda  
  // numerator = 3 * x^2
  mul256(temp, P->x, P->x); // x^2
  mul256(numerator, temp, three); // 3 * x^2

  // denominator = 2 * y
  add256(denominator, P->y, P->y); // 2 * y

  // lambda = numerator / denominator 
  div_mod_p(lambda, numerator, denominator);

  // Calculate new point
  // x_R = lambda^2 - 2 * x
  mul256(temp, lambda, lambda); 
  sub256(temp, temp, P->x); // lambda^2 - x
  sub256(R->x, temp, P->x); // lambda^2 - 2*x

  // y_R = lambda * (x - x_R) - y
  sub256(temp, P->x, R->x);
  mul256(temp, lambda, temp);
  sub256(R->y, temp, P->y); 
}

// Point multiplication: R = k * P
void point_mul(Point *R, const uint8_t *k, const Point *P) {
    Point result = {/* Initialize to point at infinity */};
    Point current = *P;
    
    for (int i = 0; i < 256; i++) {
        uint8_t ki = (k[i / 8] >> (i % 8)) & 1;  // i-th bit of k
        if (ki) {
            point_add(&result, &result, &current);
        }
        point_double(&current, &current);
    }

    *R = result;
}

// Function to compress public key
void compress_pubkey(const Point *public_key, uint8_t *compressed) {
    uint8_t y_is_even = !(public_key->y[31] & 1);
    compressed[0] = y_is_even ? 0x02 : 0x03;
    memcpy(&compressed[1], public_key->x, 32);
}

int main() {
    // Your private key (hex format)
    const uint8_t private_key[32] = {0x2E, 0x09, 0x16, 0x5B, 0x25, 0x7A, 0x4C, 0x3E, 0x52, 0xC9, 0xF4, 0xFA, 0xA6, 0x32, 0x2C, 0x66, 0xCE, 0xDE, 0x80, 0x7B, 0x7D, 0x6B, 0x4E, 0xC3, 0x96, 0x08, 0x20, 0x79, 0x5E, 0xE5, 0x44, 0x7F};

    printf("Private key: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", private_key[i]);
    }

    // Generator point G
    Point G = {
        .x = {0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98},
        .y = {0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8, 0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8}
    };

    // Derive public key
    Point public_key;
    point_mul(&public_key, private_key, &G);

    // Compress the public key
    uint8_t compressed_pubkey[33];
    compress_pubkey(&public_key, compressed_pubkey);

    // Print the compressed public key
    printf("\nCompressed public key: ");
    for (int i = 0; i < 33; i++) {
        printf("%02x", compressed_pubkey[i]);
    }
    printf("\n");

    return 0;
}
