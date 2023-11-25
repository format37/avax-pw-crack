#include <stdio.h>
#include <cuda.h>
#include "bignum.h"

__device__ int simple_BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d)
{
    // Check for division by zero
    if (d->top == 0) {
        return 0; // Error code
    }

    // Perform the modulo operation; this is a simplified operation assuming single-precision
    BN_ULONG remainder = m->d[0] % d->d[0];

    // Check the sign and adjust if necessary
    if (m->neg) {
        remainder = d->d[0] - remainder;
    }

    // Update the result BIGNUM
    r->d[0] = remainder;
    r->top = 1; // Simplified; assuming single-precision arithmetic
    r->neg = 0; // Result is always non-negative

    return 1; // Success
}

__device__ void big_num_add_mod(BN_ULONG *result, BN_ULONG *a, BN_ULONG *b, BN_ULONG *n, int num_words) {
    BN_ULONG carry = 0;
    for (int i = num_words - 1; i >= 0; i--) {
        unsigned long long sum = (unsigned long long) a[i] + (unsigned long long) b[i] + carry; // Use 64-bit to prevent overflow
        result[i] = (BN_ULONG) (sum % 0x100000000);  // Keep lower 32 bits
        carry = (BN_ULONG) (sum >> 32); // Upper 32 bits become carry
    }

    // Modular reduction: simply subtract n from result if result >= n
    for (int i = 0; i < num_words; i++) {
        if (result[i] < n[i]) return; // Early exit if we find a smaller component
        if (result[i] > n[i]) break; // Continue if we find a larger component
    }
    // At this point, we know result >= n, so perform result -= n
    carry = 0;
    for (int i = num_words - 1; i >= 0; i--) {
        long long diff = (long long) result[i] - (long long) n[i] - carry; // Use 64-bit to prevent underflow
        if (diff < 0) {
            diff += 0x100000000; // Borrow from next word
            carry = 1;
        } else {
            carry = 0;
        }
        result[i] = (BN_ULONG) diff;
    }
}

__device__ void robust_BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d) {
    // Copy m into r
    for (int i = 0; i < m->top; ++i) {
        r->d[i] = m->d[i];
    }
    r->top = m->top;
    r->neg = 0;  // Result is non-negative

    // Now we'll reduce r modulo d, using simple division
    for (int i = 0; i < r->top; ++i) {
        if (r->d[i] >= d->d[0]) {
            BN_ULONG quotient = r->d[i] / d->d[0];
            BN_ULONG remainder = r->d[i] % d->d[0];

            // Subtract quotient*d from r
            BN_ULONG borrow = 0;
            for (int j = 0; j < d->top; ++j) {
                unsigned long long sub = (unsigned long long) r->d[i+j] - (unsigned long long) d->d[j] * quotient - borrow;
                r->d[i+j] = (BN_ULONG) (sub % 0x100000000);
                borrow = (BN_ULONG) (sub >> 32);
            }

            // Add back the remainder at position i
            unsigned long long sum = (unsigned long long) r->d[i] + (unsigned long long) remainder;
            r->d[i] = (BN_ULONG) (sum % 0x100000000);
            BN_ULONG carry = (BN_ULONG) (sum >> 32);

            // Propagate any carry
            for (int j = i+1; j < r->top && carry; ++j) {
                sum = (unsigned long long) r->d[j] + carry;
                r->d[j] = (BN_ULONG) (sum % 0x100000000);
                carry = (BN_ULONG) (sum >> 32);
            }

            // If there's still a carry, increase the size of r
            if (carry) {
                r->d[r->top] = carry;
                r->top++;
            }
        }
    }
}

// Public key derivation ++
/*#define MAX_BIGNUM_WORDS 8 // Assuming 256-bit numbers
#define BN_ULONG_NUM_BITS (sizeof(BN_ULONG) * 8)
#define MAX_BIGNUM_SIZE 16 // For holding up to a 512-bit number TODO: maybe 256 ?
//#define MAX_BIGNUM_SIZE 8 // For holding up to a 512-bit number TODO: maybe 256 ?*/
__device__ BIGNUM CURVE_P;
__device__ BIGNUM CURVE_A;
__device__ BIGNUM CURVE_B;
__device__ BIGNUM CURVE_GX;
__device__ BIGNUM CURVE_GY;
__device__ BN_ULONG CURVE_P_d[8];
__device__ BN_ULONG CURVE_A_d[8];
__device__ BN_ULONG CURVE_B_d[8];
__device__ BN_ULONG CURVE_GX_d[8];
__device__ BN_ULONG CURVE_GY_d[8];

struct EC_POINT {
  BIGNUM x; 
  BIGNUM y;
};

__device__ void bn_div(BIGNUM *a, BIGNUM *b, BIGNUM *q, BIGNUM *r);
__device__ void bn_mul(BIGNUM *a, BIGNUM *b, BIGNUM *product);
// __device__ void bn_sub(BIGNUM *a, BIGNUM *b, BIGNUM *r);

/*__device__ void bn_init_zero(BIGNUM *bn, int top) {
    // Note: This assumes that memory for bn->d has already been allocated
    // with the appropriate size beforehand.
    for (int i = 0; i < top; i++) {
        bn->d[i] = 0; // Set all digits to 0
    }
    bn->top = top; // Set the number of active words
    bn->neg = 0;   // Set the number as positive
}*/

__device__ void set_bn(BIGNUM *dest, const BIGNUM *src) {
    printf("set_bn 0\n");

    // Check if dest has enough space to copy from src
    if (dest->dmax < src->top) {
        // Handle the situation appropriately
        // Depending on how memory is managed, this could be an error or resize operation
        return;
    }

    // Copy over the significant words from source to destination.
    for (int i = 0; i < src->top; ++i) {
        printf("set_bn 1.%d\n", i);
        dest->d[i] = src->d[i];
    }

    // Zero out any remaining entries in the array if the source 'top' is less than the dest 'dmax'
    for (int i = src->top; i < dest->dmax; ++i) {
        printf("set_bn 2.%d\n", i);
        dest->d[i] = 0;
    }

    printf("set_bn 3\n");

    // Set the 'top' and 'neg' flags after zeroing
    dest->top = src->top;
    dest->neg = src->neg;
}

// In the current structure, we might use a specific value (e.g., 0 or -1) 
// to represent the components of the point at infinity.

// A version that uses 0 to signify the point at infinity could be:
__device__ int point_is_at_infinity(EC_POINT *P) {
    /*printf("# point_is_at_infinity:\n");
    bn_print("P->x: ", &P->x);
    bn_print("P->y: ", &P->y);
    printf("# P->x.top: %d\n", P->x.top);*/
    /*if (P->x.top == 0) {
        printf("returning 1\n");
        return 1; // P is the point at infinity
    }
    printf("returning 0\n");
    return 0; // P is not the point at infinity*/
    return P->x.top == 0; // Assuming a valid x coordinate can never have top == 0, except for the point at infinity
    /*
    // Assuming the x-coordinate is represented as an array of BN_ULONG
    // with 'top' items, and that the point at infinity has all its
    // BN_ULONGs set to 0.
    
    // If we like to detect a "point at infinity" by checking if the first word
    // is zero and making an assumption that this can only happen for the point at infinity:
    if (P->x.top == 0 && P->x.d[0] == 0) {
        return 1; // P is the point at infinity
    }

    return 0; // P is not the point at infinity
    */
}

// __device__ void mod_inv(BIGNUM *value, BIGNUM *mod, BIGNUM *inv);
// __device__ int extended_gcd(BIGNUM *a, BIGNUM *p, BIGNUM *x, BIGNUM *y);

// Assuming 'a' and 'mod' are coprime, output 'x' such that: a*x ≡ 1 (mod 'mod')
// Pseudo code for Extended Euclidean Algorithm in CUDA
__device__ int extended_gcd(BIGNUM *a, BIGNUM *mod, BIGNUM *x, BIGNUM *y) {
    // Initialization of prev_x, x, last_y, and y is omitted here but important.
    BIGNUM prev_x, last_y, last_remainder, remainder, quotient, temp;
    // Initialize prev_x = 1, x = 0, last_y = 0, y = 1 
    // Initialize last_remainder = mod, remainder = a

    // Initialize a BIGNUM for zero.
    BIGNUM zero;
    BN_ULONG zero_d[1] = {0}; // Assuming BN_ULONG is the type used to represent a single "word" of the BIGNUM.

    zero.d = zero_d;
    // zero.top = (zero_d[0] != 0); // If we've set zero_d[0] to 0, zero's top should be zero, implying an actual value of 0.
    zero.top = 0;
    zero.dmax = 1; // The maximum number of "words" in the BIGNUM. Since zero is just 0, this is 1.

    BIGNUM *temp_remainder = new BIGNUM(); // If dynamic memory is allowed - or statically allocate enough space if not

    while (bn_cmp(&remainder, &zero) != 0) {
        // bn_div(&last_remainder, &remainder, &quotient);
        bn_div(&last_remainder, &remainder, &quotient, temp_remainder); // Now using 4 arguments
        BIGNUM swap_temp = last_remainder; // Temporary storage for the swap
        last_remainder = *temp_remainder;
        *temp_remainder = swap_temp;

        bn_mul(&quotient, x, &temp); // temp = quotient*x
        bn_sub(&prev_x, &temp, &prev_x); // new prev_x = prev_x - temp
        bn_mul(&quotient, y, &temp); // temp = quotient*y
        bn_sub(&last_y, &temp, &last_y); // new last_y = last_y - temp
        
        // Swap last_remainder with remainder
        // Swap prev_x with x
        // Swap last_y with y
    }

    // Clean up
    delete temp_remainder; // Only if dynamic memory is allowed - if you statically allocated, this is unnecessary
    
    set_bn(x, &prev_x);
    set_bn(y, &last_y);

    return 1; // In this simplified version, we'd return the gcd, but we're presuming a==1
}

__device__ void mod_inv(BIGNUM *value, BIGNUM *mod, BIGNUM *inv) {
    printf("mod_inv 0\n");
    BIGNUM x, y;
    // You need to make sure that BIGNUM x, y are initialized properly with minted memory
    // You also need a proper gcd implementation on GPU here.
    int g = extended_gcd(value, mod, &x, &y);
    
    // In case x is negative, we add mod to it, assuming mod>0
    if (x.neg) {
        printf("mod_inv a.0\n");
        // BN_ULONG zero = 0;
        bn_add(&x, mod, inv);
        printf("mod_inv a.1\n");
        bn_mod(inv, mod, inv);
        printf("mod_inv a.2\n");
    } else {
        printf("mod_inv b.0\n");
        bn_mod(&x, mod, inv);
        printf("mod_inv b.1\n");
    }
}

/*__device__ void bn_sub_v2(BIGNUM *a, BIGNUM *b, BIGNUM *r) {
    int max = a->top > b->top ? a->top : b->top;
    BN_ULONG borrow = 0;
    
    for (int i = 0; i < max; ++i) {
        printf("# 4.%d\n", i);
        BN_ULONG ai = (i < a->top) ? a->d[i] : 0;
        BN_ULONG bi = (i < b->top) ? b->d[i] : 0;

        // Check if a subtraction would cause a borrow
        if (ai >= bi + borrow) {
            printf("# 5\n");
            printf("r->top: %d\n", r->top);
            printf("i: %d\n", i);
            printf("r->d[i]: %llu\n", r->d[i]);
            printf("ai: %llu\n", ai);
            printf("bi: %llu\n", bi);
            printf("borrow: %llu\n", borrow);            
            r->d[i] = ai - bi - borrow;
            printf("# 6\n");
            borrow = 0;
        } else {
            // Borrow from the next highest bit
            r->d[i] = (1ULL << (sizeof(BN_ULONG) * 8)) + ai - bi - borrow;
            borrow = 1;
        }
    }
    printf("# 8\n");
    // Set result top and sign
    r->top = a->top; // r will have at most as many words as a
    for (int i = r->top - 1; i >= 0; --i) {
        if (r->d[i] != 0) {
            break;
        }
        r->top--; // Reduce top for each leading zero
    }

    // Detect underflow
    if (borrow != 0) {
        // Handle result underflow if needed (b > a)
        printf("Underflow detected\n");
        // Set r to correct value or raise an error
    }
    
    r->neg = 0; // Assuming we don't want negative numbers, otherwise set sign properly
}*/




__device__ void bn_mul(BIGNUM *a, BIGNUM *b, BIGNUM *product) {
    // Assuming all BIGNUMs are initialized, and all the `d` arrays have enough allocated memory.
    
    // Initialize product to zero.
    for (int i = 0; i < product->dmax; i++) {
        product->d[i] = 0;
    }
    product->top = 0;

    // Multiply each digit of a by each digit of b, accumulate results in product
    for (int i = 0; i < a->top; i++) {
        BN_ULONG carry = 0;
        for (int j = 0; j < b->top || carry; j++) {
            // Perform the multiplication (and add the carry from the previous operation)
            unsigned long long sum = product->d[i + j] + carry +
                (j < b->top ? ((unsigned long long)a->d[i] * b->d[j]) : 0);

            product->d[i + j] = (BN_ULONG)(sum & 0xFFFFFFFF); // Cast here depends on the size of BN_ULONG
            
            // Compute the carry for the next round of addition
            carry = (BN_ULONG)(sum >> 32); // Assuming BN_ULONG is 32-bits
        }

        // Update the top, which tracks the number of valid words in the product
        // This assumes that bn_add updates product->top.
        if (i + b->top > product->top) {
            product->top = i + b->top;
        }
    }

    // Now product contains the product of a and b, without modulo operation.
    // If necessary, perform a modulo operation here (modular reduction), or separately after calling bn_mul.
}

__device__ void bn_add_bit(BIGNUM *a, int bit_index) {
    // Determine the word in the array where this bit resides.
    int word_index = bit_index / (sizeof(BN_ULONG) * 8);
    int bit_in_word = bit_index % (sizeof(BN_ULONG) * 8);

    // Set this bit. BN_ULONG is assumed to be large enough to handle the shifts without overflow.
    BN_ULONG bit_to_set = ((BN_ULONG)1) << bit_in_word;

    // Add the bit to the BIGNUM. This is safe from overflow because we're only setting one bit.
    a->d[word_index] |= bit_to_set;

    // Update 'top'. If we added a bit beyond the current 'top', we'll need to expand it.
    if (word_index >= a->top) {
        // Make sure we've added a bit that's not in the leading zeroes of the BIGNUM.
        // If so, `top` needs to reflect this new significant word.
        a->top = word_index + 1;

        // Ensure all bits above the current one are set to 0 in the new top 'word'.
        for (int i = bit_in_word + 1; i < sizeof(BN_ULONG) * 8; i++) {
            a->d[word_index] &= ~(((BN_ULONG)1) << i);
        }
    }
}

__device__ int bn_is_bit_set(const BIGNUM *bn, int bit_index) {
    // Check if the bit index is within the range of the BIGNUM's length
    if (bit_index < 0 || bit_index >= bn->top * BN_ULONG_NUM_BITS) {
        return 0; // Bit out of range, return 0 indicating not set
    }

    // Calculate which word and which bit within that word we are interested in
    int word_index = bit_index / BN_ULONG_NUM_BITS;
    int bit_position = bit_index % BN_ULONG_NUM_BITS;

    // Create a mask for the bit within the word
    BN_ULONG mask = (BN_ULONG)1 << bit_position;

    // Check if the bit is set and return the appropriate value
    return (bn->d[word_index] & mask) ? 1 : 0;
}

__device__ void bn_lshift(BIGNUM *a, int shift) {
    if (shift <= 0) {
        // No shift or invalid shift count; do nothing.
        return;
    }

    // Perform the shift for each word from the most significant down to the least significant.
    BN_ULONG carry = 0;
    for (int i = a->top - 1; i >= 0; --i) {
        BN_ULONG new_carry = a->d[i] >> (BN_ULONG_NUM_BITS - shift); // Capture the bits that will be shifted out.
        a->d[i] = (a->d[i] << shift) | carry; // Shift current word and add bits from previous carry.
        carry = new_carry; // Update carry for the next iteration.
    }

    // Update the 'top' if the left shift carried out of the msb.
    if (carry != 0) {
        if (a->top < a->dmax) {
            a->d[a->top] = carry; // Assign the carry to the new most significant word.
            a->top++; // Increase the top to account for the new most significant word.
        } else {
            // Handle overflow case where there's no room for an extra word.
            // This would require either halting with an error or reallocating a->d.
            printf("Error: no room for extra word in bn_lshift\n");
        }
    }
}

__device__ void bn_div(BIGNUM *a, BIGNUM *b, BIGNUM *q, BIGNUM *r) {
    // Initialize quotient and remainder to zero.
    for (int i = 0; i < q->dmax; ++i) q->d[i] = 0;
    for (int i = 0; i < r->dmax; ++i) r->d[i] = 0;
    
    // Initialize remainder with dividend 'a'.
    set_bn(r, a);

    // Normalize based on the highest set bit of divisor 'b'
    int n = b->top * sizeof(BN_ULONG) * 8; // n is total number of bits in b
    
    // Find the highest set bit for normalization.
    while (n > 0 && !bn_is_bit_set(b, n - 1)) --n;
    
    // Long division algorithm.
    for (int i = a->top * sizeof(BN_ULONG) * 8 - n; i >= 0; --i) {
        // Shift q and r left by 1 bit.
        bn_lshift(q, 1);
        bn_lshift(r, 1);
        
        // If bit 'i' of a is set, add 1 to r.
        if (bn_is_bit_set(a, i)) {
            bn_add_bit(r, 0); // Assuming you have a function to add a bit at position 0.
        }
        
        // If r >= b, set bit 0 of q and subtract b from r.
        if (bn_cmp(r, b) >= 0) {
            bn_sub(r, b, r);
            bn_add_bit(q, 0); // Assuming you have a function to add a bit at position 0.
        }
    }
}

// __device__ void mod_mul(BIGNUM *a, BIGNUM *b, BIGNUM *mod, BIGNUM *result);

__device__ void mod_mul(BIGNUM *a, BIGNUM *b, BIGNUM *mod, BIGNUM *result) {
    printf("mod_mul 0\n");
    // Product array to store the intermediate multiplication result
    BN_ULONG product_d[MAX_BIGNUM_SIZE] ={0}; // All elements initialized to 0
    // Ensure that 'product' uses this pre-allocated array
    BIGNUM product = { product_d, 0, MAX_BIGNUM_SIZE };
    printf("mod_mul 1\n");
    // Now, you can call the bn_mul function and pass 'product' to it
    bn_mul(a, b, &product);
    printf("mod_mul 2\n");
    bn_mod(&product, mod, result);
    printf("mod_mul 3\n");

    // Wipe the product memory if necessary
    for (int i = 0; i < MAX_BIGNUM_SIZE; ++i) {
        product_d[i] = 0;
    }
}

__device__ void point_double(EC_POINT *P, EC_POINT *R, BIGNUM *p) {
    // Temporary storage for the calculations
    BIGNUM s, xR, yR, m;
    printf("point_double 0\n");
    if (point_is_at_infinity(P)) {
        printf("point_double 1\n");
        // Point doubling at infinity remains at infinity
        set_bn(&R->x, &P->x);  // Copying P->x to R->x, assuming these are in the proper zeroed state
        set_bn(&R->y, &P->y);  // Copying P->y to R->y
        printf("# 2\n");
        return;
    }
    printf("point_double 3\n");

    // Calculate m = 3x^2 + a (a is zero for secp256k1)
    mod_mul(&P->x, &P->x, p, &m);  // m = x^2 mod p
    printf("point_double 4\n");
    set_bn(&s, &m);                 // s = x^2 (Since we use a=0 in secp256k1, skip adding 'a')
    bn_add(&m, &m, &s);             // s = 2x^2
    bn_add(&s, &m, &s);             // s = 3x^2
    
    // Calculate s = (3x^2 + a) / (2y) = (s) / (2y)
    // First, compute the modular inverse of (2y)
    BIGNUM two_y;
    printf("point_double 5\n");
    set_bn(&two_y, &P->y);         // Assuming set_bn simply duplicates P->y
    printf("point_double 6\n");
    bn_add(&two_y, &two_y, &two_y); // two_y = 2y
    BIGNUM inv_two_y;
    printf("point_double 7\n");
    mod_inv(&two_y, p, &inv_two_y);  // Compute the inverse of 2y
    printf("point_double 8\n");

    mod_mul(&s, &inv_two_y, p, &s);  // Finally, s = (3x^2 + a) / (2y) mod p
    
    // Compute xR = s^2 - 2x mod p
    mod_mul(&s, &s, p, &xR);        // xR = s^2 mod p    
    set_bn(&m, &P->x);              // m = x
    
    bn_add(&m, &m, &m);             // m = 2x
    bn_sub(&xR, &m, &xR);           // xR = s^2 - 2x
    bn_mod(&xR, p, &xR);            // Modulo operation

    // Compute yR = s * (x - xR) - y mod p
    bn_sub(&P->x, &xR, &yR);        // yR = x - xR
    mod_mul(&s, &yR, p, &yR);       // yR = s * (x - xR)
    bn_sub(&yR, &P->y, &yR);        // yR = s * (x - xR) - y
    bn_mod(&yR, p, &yR);            // Modulo operation

    // Copy results to R only after all calculations are complete to allow in-place doubling (P == R)
    set_bn(&R->x, &xR);
    set_bn(&R->y, &yR);
}

/*__device__ void point_add_v0(EC_POINT *P, EC_POINT *Q, EC_POINT *R, BIGNUM *p) {
    printf("# 1\n");
    // Check if one of the points is the point at infinity
    if (point_is_at_infinity(P)) {
        *R = *Q;
        return;
    }
    
    if (point_is_at_infinity(Q)) {
        *R = *P;
        return;
    }
    
    // Check if P == Q (point doubling)
    if (bn_cmp(&P->x, &Q->x) == 0 && bn_cmp(&P->y, &Q->y) == 0) {
        // call point_double
        // point_double(P, R, p);
        
        // We don't need to double the point. We can just add it to itself.
        point_add(P, P, R, p);
        return;
    }
    
    BIGNUM s, m, xR, yR;

    // Calculate slope (s = (yQ - yP) * inv(xQ - xP) mod p)
    BIGNUM tmp1, tmp2;
    printf("# 2\n");
    bn_sub(&Q->y, &P->y, &tmp1); // yQ - yP
    printf("# 100\n");
    bn_sub(&Q->x, &P->x, &tmp2); // xQ - xP
    mod_inv(&tmp2, p, &tmp2);     // inv(xQ - xP)
    mod_mul(&tmp1, &tmp2, p, &s); // (yQ - yP) * inv(xQ - xP)
    
    // Calculate xR (xR = s^2 - xP - xQ mod p)
    mod_mul(&s, &s, p, &xR); // s^2
    bn_sub(&xR, &P->x, &xR); // s^2 - xP
    bn_sub(&xR, &Q->x, &xR); // s^2 - xP - xQ
    bn_mod(&xR, p, &xR);     // mod p

    // Calculate yR (yR = s * (xP - xR) - yP mod p)
    bn_sub(&P->x, &xR, &yR); // xP - xR
    mod_mul(&s, &yR, p, &yR); // s * (xP - xR)
    bn_sub(&yR, &P->y, &yR);  // s * (xP - xR) - yP
    bn_mod(&yR, p, &yR);      // mod p

    // Set result
    set_bn(&R->x, &xR);
    set_bn(&R->y, &yR);
}*/

__device__ void point_add(EC_POINT *P, EC_POINT *Q, EC_POINT *R, BIGNUM *p) {
    // Check if one of the points is the point at infinity
    if (point_is_at_infinity(P)) {
        *R = *Q;
        return;
    }
    
    if (point_is_at_infinity(Q)) {
        *R = *P;
        return;
    }
    
    // Calculate slope (s = (yQ - yP) * inv(xQ - xP) mod p)
    
    /*BIGNUM s, xR, yR;
    BIGNUM tmp1, tmp2;

    // Calculate s = (yQ - yP) / (xQ - xP)
    bn_sub(&Q->y, &P->y, &tmp1); // tmp1 = yQ - yP
    bn_sub(&Q->x, &P->x, &tmp2); // tmp2 = xQ - xP
    mod_inv(&tmp2, p, &tmp2);    // tmp2 = inv(xQ - xP)
    mod_mul(&tmp1, &tmp2, p, &s); // s = (yQ - yP) * inv(xQ - xP)*/
    // Allocate memory on the stack or in shared/dynamic memory for the BIGNUMs and their 'd' arrays
    BN_ULONG tmp1_d[MAX_BIGNUM_WORDS], tmp2_d[MAX_BIGNUM_WORDS];
    BN_ULONG s_d[MAX_BIGNUM_WORDS];
    BN_ULONG xR_d[MAX_BIGNUM_WORDS], yR_d[MAX_BIGNUM_WORDS];

    // Initialize temporary BIGNUMs used for calculations
    BIGNUM tmp1, tmp2, s, xR, yR;
    tmp1.d = tmp1_d; init_zero(&tmp1, MAX_BIGNUM_WORDS);
    tmp2.d = tmp2_d; init_zero(&tmp2, MAX_BIGNUM_WORDS);
    s.d = s_d;       init_zero(&s, MAX_BIGNUM_WORDS);
    xR.d = xR_d;     init_zero(&xR, MAX_BIGNUM_WORDS);
    yR.d = yR_d;     init_zero(&yR, MAX_BIGNUM_WORDS);

    // Calculate xR = s^2 - xP - xQ
    mod_mul(&s, &s, p, &xR);   // xR = s^2
    bn_sub(&xR, &P->x, &xR);   // xR = xR - xP (s^2 - xP)
    bn_sub(&xR, &Q->x, &xR);   // xR = xR - xQ (s^2 - xP - xQ)
    bn_mod(&xR, p, &xR);       // xR = xR mod p

    // Calculate yR = s * (xP - xR) - yP
    bn_sub(&P->x, &xR, &yR);   // yR = xP - xR
    mod_mul(&s, &yR, p, &yR);  // yR = s * (xP - xR)
    bn_sub(&yR, &P->y, &yR);   // yR = yR - yP (s * (xP - xR) - yP)
    bn_mod(&yR, p, &yR);       // yR = yR mod p

    // Set result
    set_bn(&R->x, &xR);
    set_bn(&R->y, &yR);
}

__device__ void bignum_to_bit_array(const BIGNUM *n, unsigned int *bits) {
    int index = 0;
    for (int i = 0; i < n->top; ++i) {
        BN_ULONG word = n->d[i];
        for (int j = 0; j < 32; ++j) {  // Assuming BN_ULONG is 32 bits
            bits[index++] = (word >> j) & 1;
        }
    }
}

__device__ void init_point_at_infinity(EC_POINT *P) {
    // For the x and y coordinates of P, we'll set the 'top' to 0,
    // which is our chosen convention for representing the point at infinity.

    P->x.top = 0; // No valid 'words' in the BIGNUM representing x
    P->y.top = 0; // No valid 'words' in the BIGNUM representing y

    // If 'd' arrays have been allocated, set them to zero as well.
    // memset could potentially be used for this if available and if 'd' is allocated.
    
    for (int i = 0; i < P->x.dmax; ++i) {
        P->x.d[i] = 0;
    }
    for (int i = 0; i < P->y.dmax; ++i) {
        P->y.d[i] = 0;
    }
    
    // Alternatively, if you use flags or other conventions for points at infinity,
    // set them accordingly here.
}

__device__ EC_POINT ec_point_scalar_mul(EC_POINT *point, BIGNUM *scalar, BIGNUM *curve_order) {
    EC_POINT current = *point;                       // This initializes the current point with the input point
    EC_POINT result;                                 // Initialize the result variable, which accumulates the result
    init_point_at_infinity(&result);                 // Initialize it to the point at infinity

    // Convert scalar BIGNUM to an array of integers that's easy to iterate bit-wise
    unsigned int bits[256];                          // Assuming a 256-bit scalar
    bignum_to_bit_array(scalar, bits);               // You will need to implement bignum_to_bit_array()

    // printf("coef hex: %s\n", bignum_to_hex(scalar)); // Convert BIGNUM to hex string for printing
    bn_print("coef: ", scalar);                      // Print the scalar

    for (int i = 0; i < 256; i++) {                 // Assuming 256-bit scalars
        // printf("0 x: %s\n", bignum_to_hex(&current.x));
        bn_print("0 x: ", &current.x);
        // printf("0 y: %s\n", bignum_to_hex(&current.y));
        bn_print("0 y: ", &current.y);

        if (bits[i]) {                              // If the i-th bit is set
            printf("# 0\n");
            // point_add(&result, &current, &result);  // Add current to the result
            // point_add(&result, &current, &result, &field_order);  // Add current to the result
            point_add(&result, &current, &result, curve_order);  // Add current to the result
            printf("# b\n");
            // printf("1 x: %s\n", bignum_to_hex(&result.x));
            bn_print("1 x: ", &result.x);
            // printf("1 y: %s\n", bignum_to_hex(&result.y));
            bn_print("1 y: ", &result.y);

        }
        printf("# c\n");

        //point_double(&current, &current);           // Double current
        // point_double(&current, &current, &field_order);  // Double current and store the result in current
        // point_double(&current, &current, curve_order);

        // We don't need to double the point. We can just add it to itself.
        point_add(&current, &current, &current, curve_order);

        // printf("2 x: %s\n", bignum_to_hex(&current.x));
        bn_print("2 x: ", &current.x);
        // printf("2 y: %s\n", bignum_to_hex(&current.y));
        bn_print("2 y: ", &current.y);
    }

    // printf("Final x: %s\n", bignum_to_hex(&result.x));
    bn_print("Final x: ", &result.x);
    // printf("Final y: %s\n", bignum_to_hex(&result.y));
    bn_print("Final y: ", &result.y);

    return result;
}

__device__ void bn_copy(BIGNUM *dest, BIGNUM *src) {
    // Copy the 'top' and 'neg' fields
    dest->top = src->top;
    dest->neg = src->neg;

    // Copy the 'd' array
    for (int i = 0; i < src->top; ++i) {
        dest->d[i] = src->d[i];
    }
}

//bn_is_zero
__device__ int bn_is_zero(BIGNUM *a) {
    for (int i = 0; i < a->top; ++i) {
        if (a->d[i] != 0) {
            return 0;
        }
    }
    return 1;
}

__device__ int bn_mod_inverse(BIGNUM *r, BIGNUM *a, BIGNUM *m) {
    BN_ULONG tmp_d[MAX_BIGNUM_WORDS];
    // Initialize variables
    BIGNUM u, v, x1, x2, q, r_, tmp, bn_one;
    u.d = tmp_d; v.d = tmp_d; x1.d = tmp_d; x2.d = tmp_d; q.d = tmp_d; r_.d = tmp_d; tmp.d = tmp_d; bn_one.d = tmp_d;
    init_zero(&u, MAX_BIGNUM_WORDS);
    init_zero(&v, MAX_BIGNUM_WORDS);
    init_zero(&x1, MAX_BIGNUM_WORDS);
    init_zero(&x2, MAX_BIGNUM_WORDS);
    init_zero(&q, MAX_BIGNUM_WORDS);
    init_zero(&r_, MAX_BIGNUM_WORDS);
    init_zero(&tmp, MAX_BIGNUM_WORDS);
    init_zero(&bn_one, MAX_BIGNUM_WORDS);

    bn_copy(&u, a);
    bn_copy(&v, m);
    x2.d[0] = 1; // x2 = 1 initially
    bn_one.d[0] = 1; // bn_one = 1

    // The algorithm requires working with positive numbers, so we ignore signs
    a->neg = 0;
    m->neg = 0;

    while (!bn_is_zero(&u)) {
        // q = v / u;
        bn_div(&q, NULL, &v, &u);

        // tmp = v - q * u;
        bn_mul(&tmp, &q, &u);
        bn_sub(&tmp, &v, &tmp);

        // v = u;
        bn_copy(&v, &u);

        // u = tmp;
        bn_copy(&u, &tmp);

        // tmp = x2 - q * x1;
        bn_mul(&tmp, &q, &x1);
        bn_sub(&tmp, &x2, &tmp);

        // x2 = x1;
        bn_copy(&x2, &x1);

        // x1 = tmp;
        bn_copy(&x1, &tmp);
    }

    // Check for inverse not existing
    if (bn_cmp(&v, &bn_one) != 0) {
        // Inverse does not exist
        return 0;
    }

    // Adjust result if negative
    if (x2.neg) {
        bn_add(&x2, m, &x2);
    }

    bn_copy(&r_, &x2);
    return 1;
}

__device__ void point_add_new(EC_POINT *self, EC_POINT *other, EC_POINT *result) {
    printf("self != other\n");
    BIGNUM s_left;

    // init as zero
    BN_ULONG tmp_d[MAX_BIGNUM_WORDS];
    s_left.d = tmp_d; 
    init_zero(&s_left, MAX_BIGNUM_WORDS);

     // Step 1: Compute the difference in y coordinates: dy = y2 - y1
    // Formula (x3, y3) = (x1, y1) + (x2, y2)
    // BIGNUM s_left = (other->y - self->y);
    bn_sub(&other->y, &self->y, &s_left);
    bn_print("s_left: ", &s_left);

    // Step 2: Compute the difference in x coordinates: dx = x2 - x1
    // s_right_a = other.x - self.x
    BIGNUM s_right_a;
    s_right_a.d = tmp_d;
    init_zero(&s_right_a, MAX_BIGNUM_WORDS);
    bn_sub(&other->x, &self->x, &s_right_a);
    bn_print("s_right_a: ", &s_right_a);

    // s_right_b = -1
    /*BIGNUM s_right_b;
    s_right_b.d = tmp_d;
    init_zero(&s_right_b, MAX_BIGNUM_WORDS);
    s_right_b.d[0] = 1;
    s_right_b.neg = 1;
    bn_print("s_right_b: ", &s_right_b);*/

    // s_right_c is p of secp256k1
    /*BIGNUM p;
    // 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    BN_ULONG p[8] = {
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,  
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFC2F
    };
    p.d = s_right_c_d;
    p.top = 8;
    p.neg = 0;
    bn_print("p: ", &p);*/

    // s_right = pow(s_right_a, s_right_b, s_right_c)
    /*BIGNUM s_right;
    s_right.d = tmp_d;
    init_zero(&s_right, MAX_BIGNUM_WORDS);
    bn_pow(&s_right_a, &s_right_b, &s_right_c, &s_right);
    bn_print("s_right: ", &s_right);*/

    // Step 3: Compute the modular inverse of dx: dx_inv = inverse_mod(dx, p)
    BIGNUM dx_inv;
    dx_inv.d = tmp_d;
    init_zero(&dx_inv, MAX_BIGNUM_WORDS);
    bn_mod_inverse(&dx_inv, &dx, &mod_p, ctx); // mod_p should be pre-initialized with the curve prime

    // Step 4: Calculate the slope s = dy * dx_inv mod p
    /*BIGNUM s;
    init_bignum(&s);
    bn_mul_mod(&s, &dy, &dx_inv, &mod_p, ctx);*/

    // Step 5: Compute new point coordinates x3 and y3
}

__device__ void testAddition() {

  // Initialize points
  EC_POINT P, Q, R;
  
  // Point 1
  BN_ULONG Px[8] = { 
    0x79BE667E, 0xF9DCBBAC, 0x55A06295, 0xCE870B07,
    0x029BFCDB, 0x2DCE28D9, 0x59F2815B, 0x16F81798
  };

  BN_ULONG Py[8] = {
    0x483ADA77, 0x26A3C465, 0x5DA4FBFC, 0x0E1108A8, 
    0xFD17B448, 0xA6855419, 0x9C47D08F, 0xFB10D4B8
  };

  // Point 2: 
  // 0xC6047F9441ED7D6D3045406E95C07CD85F59F1602472841DCC5C6D28190315EC
  BN_ULONG Qx[8] = {
    0xC6047F94, 0x41ED7D6D, 0x3045406E, 0x95C07CD8,
    0x5F59F160, 0x2472841D, 0xCC5C6D28, 0x190315EC
  };
  // 0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1230374FBFA883B3E
  BN_ULONG Qy[8] = {  
    0x1AE168FE, 0xA63DC339, 0xA3C58419, 0x466CEAEE,
    0xF7F63265, 0x3266D0E1, 0x230374FB, 0xFA883B3E
  };

  // Initialize points
  P.x.d = Px;
  P.y.d = Py;

  Q.x.d = Qx;
  Q.y.d = Qy;

  BN_ULONG Rx[8], Ry[8];
  // Initialize result point
  // init R as zero
    for (int i = 0; i < 8; i++) {
        Rx[i] = 0;
        Ry[i] = 0;
    }
  R.x.d = Rx;
  R.y.d = Ry;

 // Curve prime for secp256k1
    BN_ULONG prime[8] = {
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 
    0xBAAEDCE6, 0xAF48A03B, 0xBFD25E8C, 0xD0364141  
    };

    // Initialize curvePrime
    BIGNUM curvePrime;
    curvePrime.d = prime; 
    curvePrime.top = 8;
    curvePrime.neg = 0; 

  // Set tops and negs
    P.x.top = 8;
    P.y.top = 8;
    P.x.neg = 0;
    P.y.neg = 0;
    Q.x.top = 8;
    Q.y.top = 8;
    Q.x.neg = 0;
    Q.y.neg = 0;
    R.x.top = 8;
    R.y.top = 8;
    R.x.neg = 0;
    R.y.neg = 0;

  // Print point 1
    bn_print("Point 1 x:", &P.x);
    bn_print("Point 1 y:", &P.y);

    // Print point 2
    bn_print("Point 2 x:", &Q.x);
    bn_print("Point 2 y:", &Q.y);    

  // Call point addition
  // point_add(&P, &Q, &R, &curvePrime);
  point_add_new(&P, &Q, &R);

  // Print result
  // bn_print("Result x:", &R.x);
  // bn_print("Result y:", &R.y);

}
// Public key derivation --

__global__ void testKernel() {

    BN_CTX *ctx = BN_CTX_new();

    // Addition
    BIGNUM a;
    BIGNUM b;
    BIGNUM curveOrder;
    BIGNUM newKey;

    BN_ULONG a_d[8];
    BN_ULONG b_d[8];
    BN_ULONG newKey_d[8];
    BN_ULONG curveOrder_d[16];

    // Initialize a
    // C17747B1566D9FE8AB7087E3F0C50175B788A1C84F4C756C405000A0CA2248E1
    a_d[0] = 0xC17747B1;
    a_d[1] = 0x566D9FE8;
    a_d[2] = 0xAB7087E3;
    a_d[3] = 0xF0C50175;
    a_d[4] = 0xB788A1C8;
    a_d[5] = 0x4F4C756C;
    a_d[6] = 0x405000A0;
    a_d[7] = 0xCA2248E1;  
    a.d = a_d; 
    a.top = 8;
    a.neg = 0;

    // Initialize b
    // 6C91CEA9CF0CAC55A7596D16B56D2AEFD204BB99DD677993158A7E6564F93CDF
    b_d[0] = 0x6C91CEA9;
    b_d[1] = 0xCF0CAC55;
    b_d[2] = 0xA7596D16;
    b_d[3] = 0xB56D2AEF;
    b_d[4] = 0xD204BB99;
    b_d[5] = 0xDD677993;
    b_d[6] = 0x158A7E65;
    b_d[7] = 0x64F93CDF;
    b.d = b_d;
    b.neg = 0;
    b.top = 8;

    // Initialize newKey_d
    for (int i = 0; i < 8; i++) newKey_d[i] = 0;
    newKey.d = newKey_d;
    newKey.neg = 0;
    newKey.top = 8;

    // Initialize curveOrder_d
    // FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    curveOrder_d[0] = 0xFFFFFFFF;
    curveOrder_d[1] = 0xFFFFFFFF;
    curveOrder_d[2] = 0xFFFFFFFF;
    curveOrder_d[3] = 0xFFFFFFFE;
    curveOrder_d[4] = 0xBAAEDCE6;
    curveOrder_d[5] = 0xAF48A03B;
    curveOrder_d[6] = 0xBFD25E8C;
    curveOrder_d[7] = 0xD0364141;
    curveOrder.d = curveOrder_d;
    curveOrder.neg = 0;
    curveOrder.top = 8;

    // Print inputs
    bn_print("A: ", &a);
    bn_print("B: ", &b);

    // Add A and B
    bn_add(&a, &b, &newKey);
    
    // Print A + B
    bn_print("Debug Cuda newKey (After add): ", &newKey);

    // Modular Reduction
    BIGNUM m;
    BN_ULONG m_d[8];
    for (int i = 0; i < 8; i++) m_d[i] = 0;
    m_d[0] = 0x00000064; // 100
    m.d = m_d;
    m.top = 1;
    m.neg = 0;
    
    printf("Calling bn_nnmod\n");
    bn_mod(&newKey, &newKey, &curveOrder);

    printf("Debug Cuda newKey (expected_): 2E09165B257A4C3E52C9F4FAA6322C66CEDE807B7D6B4EC3960820795EE5447F\n");
    bn_print("Debug Cuda newKey (After mod): ", &newKey);


    // Derive the public key
    printf("Deriving the public key..\n");
    // Initialize constants
    // CURVE_P is curveOrder_d
    CURVE_P.d = curveOrder_d;
    CURVE_P.top = 8;
    CURVE_P.neg = 0;
    
    for (int i = 0; i < 8; i++) CURVE_A_d[i] = 0;
    CURVE_A.d = CURVE_A_d;
    CURVE_A.top = 8;
    CURVE_A.neg = 0;
    
    // For secp256k1, CURVE_B should be initialized to 7 rather than 0
    for (int i = 0; i < 8; i++) CURVE_B_d[i] = 0;
    CURVE_B_d[0] = 0x00000007;
    CURVE_B.d = CURVE_B_d;
    CURVE_B.top = 8;
    CURVE_B.neg = 0;

    // Generator x coordinate
    CURVE_GX_d[0] = 0x79BE667E;
    CURVE_GX_d[1] = 0xF9DCBBAC;
    CURVE_GX_d[2] = 0x55A06295;
    CURVE_GX_d[3] = 0xCE870B07;
    CURVE_GX_d[4] = 0x029BFCDB;
    CURVE_GX_d[5] = 0x2DCE28D9;
    CURVE_GX_d[6] = 0x59F2815B;
    CURVE_GX_d[7] = 0x16F81798; 

    // Generator y coordinate
    BIGNUM CURVE_GY;
    BN_ULONG CURVE_GY_d[8];
    CURVE_GY_d[0] = 0x483ADA77;
    CURVE_GY_d[1] = 0x26A3C465;
    CURVE_GY_d[2] = 0x5DA4FBFC;
    CURVE_GY_d[3] = 0x0E1108A8;
    CURVE_GY_d[4] = 0xFD17B448;
    CURVE_GY_d[5] = 0xA6855419;
    CURVE_GY_d[6] = 0x9C47D08F;
    CURVE_GY_d[7] = 0xFB10D4B8;

    // Initialize generator
    EC_POINT G;
    G.x.d = CURVE_GX_d; 
    G.y.d = CURVE_GY_d;
    // Set tops, negs
    G.x.top = 8;
    G.y.top = 8;
    G.x.neg = 0;
    G.y.neg = 0;

    // Derive public key 
    // EC_POINT publicKey = ec_point_scalar_mul(&G, &newKey, &curveOrder);

    // Print public key
    // printf("Public key:\n");
    // bn_print("Public key x: ", &publicKey.x);
    // bn_print("Public key y: ", &publicKey.y);

    testAddition();


    BN_CTX_free(ctx);

}

int main() {
    // print that we starting
    printf("Starting\n");
    testKernel<<<1,1>>>();
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("Error: %s\n", cudaGetErrorString(err));
        return -1;
    }
    cudaDeviceSynchronize();
    return 0;
}