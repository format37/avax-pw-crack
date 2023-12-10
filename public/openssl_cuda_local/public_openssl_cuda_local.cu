#include <stdio.h>
#include <cuda.h>

#define debug_print false

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
__device__ void bn_sub(BIGNUM *a, BIGNUM *b, BIGNUM *r);

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
    debug_printf("set_bn 0\n");

    // Check if dest has enough space to copy from src
    if (dest->dmax < src->top) {
        // Handle the situation appropriately
        // Depending on how memory is managed, this could be an error or resize operation
        return;
    }

    // Copy over the significant words from source to destination.
    for (int i = 0; i < src->top; ++i) {
        debug_printf("set_bn 1.%d\n", i);
        dest->d[i] = src->d[i];
    }

    // Zero out any remaining entries in the array if the source 'top' is less than the dest 'dmax'
    for (int i = src->top; i < dest->dmax; ++i) {
        debug_printf("set_bn 2.%d\n", i);
        dest->d[i] = 0;
    }

    debug_printf("set_bn 3\n");

    // Set the 'top' and 'neg' flags after zeroing
    dest->top = src->top;
    dest->neg = src->neg;
}

// In the current structure, we might use a specific value (e.g., 0 or -1) 
// to represent the components of the point at infinity.

// A version that uses 0 to signify the point at infinity could be:
__device__ int point_is_at_infinity(EC_POINT *P) {
    /*debug_printf("# point_is_at_infinity:\n");
    bn_print("P->x: ", &P->x);
    bn_print("P->y: ", &P->y);
    debug_printf("# P->x.top: %d\n", P->x.top);*/
    /*if (P->x.top == 0) {
        debug_printf("returning 1\n");
        return 1; // P is the point at infinity
    }
    debug_printf("returning 0\n");
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
    debug_printf("mod_inv 0\n");
    BIGNUM x, y;
    // You need to make sure that BIGNUM x, y are initialized properly with minted memory
    // You also need a proper gcd implementation on GPU here.
    int g = extended_gcd(value, mod, &x, &y);
    
    // In case x is negative, we add mod to it, assuming mod>0
    if (x.neg) {
        debug_printf("mod_inv a.0\n");
        // BN_ULONG zero = 0;
        bn_add(&x, mod, inv);
        debug_printf("mod_inv a.1\n");
        bn_mod(inv, mod, inv);
        debug_printf("mod_inv a.2\n");
    } else {
        debug_printf("mod_inv b.0\n");
        bn_mod(&x, mod, inv);
        debug_printf("mod_inv b.1\n");
    }
}

__device__ void bn_sub(BIGNUM *a, BIGNUM *b, BIGNUM *r) {
    int max = a->top > b->top ? a->top : b->top;
    BN_ULONG borrow = 0;
    
    for (int i = 0; i < max; ++i) {
        debug_printf("# 4.%d\n", i);
        BN_ULONG ai = (i < a->top) ? a->d[i] : 0;
        BN_ULONG bi = (i < b->top) ? b->d[i] : 0;

        // Check if a subtraction would cause a borrow
        if (ai >= bi + borrow) {
            debug_printf("# 5\n");
            debug_printf("r->top: %d\n", r->top);
            debug_printf("i: %d\n", i);
            debug_printf("r->d[i]: %llu\n", r->d[i]);
            debug_printf("ai: %llu\n", ai);
            debug_printf("bi: %llu\n", bi);
            debug_printf("borrow: %llu\n", borrow);            
            r->d[i] = ai - bi - borrow;
            debug_printf("# 6\n");
            borrow = 0;
        } else {
            // Borrow from the next highest bit
            r->d[i] = (1ULL << (sizeof(BN_ULONG) * 8)) + ai - bi - borrow;
            borrow = 1;
        }
    }
    debug_printf("# 8\n");
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
        debug_printf("Underflow detected\n");
        // Set r to correct value or raise an error
    }
    
    r->neg = 0; // Assuming we don't want negative numbers, otherwise set sign properly
}


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
            debug_printf("Error: no room for extra word in bn_lshift\n");
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
    debug_printf("mod_mul 0\n");
    // Product array to store the intermediate multiplication result
    BN_ULONG product_d[MAX_BIGNUM_SIZE] ={0}; // All elements initialized to 0
    // Ensure that 'product' uses this pre-allocated array
    BIGNUM product = { product_d, 0, MAX_BIGNUM_SIZE };
    debug_printf("mod_mul 1\n");
    // Now, you can call the bn_mul function and pass 'product' to it
    bn_mul(a, b, &product);
    debug_printf("mod_mul 2\n");
    
    
    bn_mod(&product, mod, result); // TODO: fix it


    debug_printf("mod_mul 3\n");

    // Wipe the product memory if necessary
    for (int i = 0; i < MAX_BIGNUM_SIZE; ++i) {
        product_d[i] = 0;
    }
}

__device__ void point_double(EC_POINT *P, EC_POINT *R, BIGNUM *p) {
    // Temporary storage for the calculations
    BIGNUM s, xR, yR, m;
    debug_printf("point_double 0\n");
    if (point_is_at_infinity(P)) {
        debug_printf("point_double 1\n");
        // Point doubling at infinity remains at infinity
        set_bn(&R->x, &P->x);  // Copying P->x to R->x, assuming these are in the proper zeroed state
        set_bn(&R->y, &P->y);  // Copying P->y to R->y
        debug_printf("# 2\n");
        return;
    }
    debug_printf("point_double 3\n");

    // Calculate m = 3x^2 + a (a is zero for secp256k1)
    mod_mul(&P->x, &P->x, p, &m);  // m = x^2 mod p
    debug_printf("point_double 4\n");
    set_bn(&s, &m);                 // s = x^2 (Since we use a=0 in secp256k1, skip adding 'a')
    bn_add(&m, &m, &s);             // s = 2x^2
    bn_add(&s, &m, &s);             // s = 3x^2
    
    // Calculate s = (3x^2 + a) / (2y) = (s) / (2y)
    // First, compute the modular inverse of (2y)
    BIGNUM two_y;
    debug_printf("point_double 5\n");
    set_bn(&two_y, &P->y);         // Assuming set_bn simply duplicates P->y
    debug_printf("point_double 6\n");
    bn_add(&two_y, &two_y, &two_y); // two_y = 2y
    BIGNUM inv_two_y;
    debug_printf("point_double 7\n");
    mod_inv(&two_y, p, &inv_two_y);  // Compute the inverse of 2y
    debug_printf("point_double 8\n");

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
    debug_printf("# 1\n");
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
    debug_printf("# 2\n");
    bn_sub(&Q->y, &P->y, &tmp1); // yQ - yP
    debug_printf("# 100\n");
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

__device__ bool bn_is_zero(BIGNUM *a) {
    for (int i = 0; i < a->top; ++i) {
        if (a->d[i] != 0) {
            return false;
        }
    }
    return true;
}

/*__device__ void bn_neg(BIGNUM *a, BIGNUM *result, BIGNUM *p) {
    if (bn_is_zero(a)) {
        // If a is 0, then -a (mod p) is also 0
        set_bn(result, a);
    } else {
        // Compute -a (mod p) as p - a
        bn_sub(p, a, result); // result = p - a
        bn_mod(result, p, result); // Ensure result is within [0, p-1]
    }
}*/
__device__ int bn_is_negative(const BIGNUM *a) {
    // Assuming the neg field is defined and holds the sign (0 for non-negative, 1 for negative)
    return a->neg != 0;
}

__device__ void point_add_v0(EC_POINT *P, EC_POINT *Q, EC_POINT *R, BIGNUM *p) {
    // Check if one of the points is the point at infinity
    if (point_is_at_infinity(P)) {
        *R = *Q;
        printf("point_is_at_infinity(P)\n");
        return;
    }
    
    if (point_is_at_infinity(Q)) {
        *R = *P;
        printf("point_is_at_infinity(Q)\n");
        return;
    }
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

// Utility function to set a BIGNUM to zero
/*__device__ void bn_zero(BIGNUM *bn) {
    if (bn != nullptr) {
        bn->neg = 0;
        bn->top = 0;

        // Assuming BIGNUM d is a pointer to an array of BN_ULONG and the array size is MAX_BIGNUM_WORDS
        for (int i = 0; i < MAX_BIGNUM_WORDS; ++i) {
            bn->d[i] = 0;
        }
    }
}*/

// Helper function to perform a deep copy of BIGNUM
__device__ void bn_copy(BIGNUM *dest, BIGNUM *src) {
    // printf("bn_copy");
    if (dest == nullptr || src == nullptr) return;

    // Copy the neg and top fields
    dest->neg = src->neg;
    dest->top = src->top;

    // Copy the array of BN_ULONG digits.
    // MAX_BIGNUM_WORDS would be the maximum number of words in the BIGNUM variable
    for (int i = 0; i < src->top; i++) {
        dest->d[i] = src->d[i];
    }

    // Set the rest of the words in dest to 0 if dest's top is larger
    for (int i = src->top; i < dest->top; i++) {
        dest->d[i] = 0;
    }
}

__device__ void copy_point(EC_POINT *dest, EC_POINT *src) {
    //printf("copy_point 0\n");
    // Assuming EC_POINT contains BIGNUM structures for x and y,
    // and that BIGNUM is a structure that contains an array of BN_ULONG for the digits,
    // along with other metadata (like size, top, neg, etc.)

    // init the dest point
    dest->x.d = new BN_ULONG[MAX_BIGNUM_WORDS];
    dest->y.d = new BN_ULONG[MAX_BIGNUM_WORDS];
    dest->x.top = 0;
    dest->y.top = 0;
    dest->x.neg = 0;
    dest->y.neg = 0;
    dest->x.dmax = MAX_BIGNUM_WORDS;
    dest->y.dmax = MAX_BIGNUM_WORDS;

    // Copy the BIGNUM x
    bn_copy(&dest->x, &src->x);
    /*for (int i = 0; i < src->x.top; i++) {
        printf("copy_point 1.%d\n", i);
        dest->x.d[i] = src->x.d[i];
    }    
    dest->x.neg = src->x.neg;
    dest->x.top = src->x.top;*/

    // Copy the BIGNUM y
    bn_copy(&dest->y, &src->y);
    /*
    for (int i = 0; i < src->y.top; i++) {
        dest->y.d[i] = src->y.d[i];
    }
    dest->y.neg = src->y.neg;
    dest->y.top = src->y.top;*/
}

__device__ void set_point_at_infinity(EC_POINT *point) {
    // Assuming EC_POINT is a structure containing BIGNUM x and y
    // and that a BIGNUM value of NULL or {0} represents the point at infinity

    // To set the point at infinity, one straightforward way is to assign
    // a null pointer to x and y if the BIGNUM structure allows it, or 
    // set their values to some predetermined sentinel value that indicates
    // the point at infinity.

    // If using the sentinel value approach - ensure BIGNUM is set in a way
    // that other functions can check for it and treat it as infinity

    // To set the point to 0 (as an example sentinel value), do:
    // bn_zero(&point->x); // A function that sets a BIGNUM to 0
    init_zero(&point->x, MAX_BIGNUM_WORDS);

    //bn_zero(&point->y); // Ensure that this logic matches how you identify point at infinity elsewhere
    init_zero(&point->y, MAX_BIGNUM_WORDS);
}

__device__ void bn_subtract(BIGNUM *result, const BIGNUM *a, const BIGNUM *b) {
    BN_ULONG borrow = 0;
    BN_ULONG temp_borrow;

    // It's assumed that BN_ULONG is an unsigned type like uint32_t or uint64_t and that
    // a and b have the same number of words (this can be adjusted as needed)
    for (int i = 0; i < MAX_BIGNUM_WORDS; ++i) {
        temp_borrow = (a->d[i] < b->d[i] + borrow); // Calculate if we need to borrow from the next digit
        result->d[i] = a->d[i] - b->d[i] - borrow;   // Perform the subtraction with previous borrow, if any
        borrow = temp_borrow;                        // Set borrow for the next iteration
    }

    // If there's remaining borrow at the end, the result is negative
    // which should not happen for BIGNUM in cryptographic applications, as these should
    // be operating in the context of a modulus (wrap around behavior). 
    // You'll need to assert borrow is 0 or handle it appropriately with your application's logic.

    // Update the metadata (top) if necessary
    // The 'top' can be adjusted based on the significant digits after subtraction.
    // result->top = ... (code to update the 'top' field of result, if BIGNUM has such a field)
}

__device__ void bn_set_word(BIGNUM *bn, BN_ULONG word) {
    // Assuming d is a pointer to an array where the BIGNUM's value is stored
    // and top is an integer representing the index of the most significant word + 1
    // Setting a BIGNUM to a single-word value means that all other words are zero.

    // Clear all words in the BIGNUM
    for (int i = 0; i < MAX_BIGNUM_WORDS; ++i) {
        bn->d[i] = 0;
    }

    // Set the least significant word to the specified value
    bn->d[0] = word;

    // Update top to indicate that there's at least one significant digit
    bn->top = (word == 0) ? 0 : 1;

    // If using a sign flag, ensure the BIGNUM is set to non-negative
    if (bn->top) {
        bn->neg = 0;
    }
}

__device__ void bn_lshift_res(BIGNUM *result, BIGNUM *a, int shift) {
    if (shift <= 0) {
        // No shift or invalid shift count; copy input to output with no modifications.
        bn_copy(result, a);
        return;
    }

    // Initialize result BIGNUM according to your BIGNUM structure definition
    // Make sure that result->d has enough space to hold the result

    // Perform the shift for each word from the least significant upwards.
    BN_ULONG carry = 0;
    for (int i = 0; i < a->top; ++i) {
        BN_ULONG new_carry = a->d[i] >> (BN_ULONG_NUM_BITS - shift); // Capture the bits that will be shifted out.
        result->d[i] = (a->d[i] << shift) | carry; // Shift current word and add bits from previous carry.
        carry = new_carry; // Update carry for the next iteration.
    }

    // Assign the carry to the new most significant word if needed.
    if (carry != 0) {
        result->d[a->top] = carry; // Assign the carry to the new most significant word.
        result->top = a->top + 1;
    } else {
        result->top = a->top;
    }

    // Initialize any remaining higher-order words to zero if necessary
    // This depends on the internals of your BIGNUM structure.
    for (int i = result->top; i < result->dmax; ++i) {
        result->d[i] = 0;
    }
}

#define WORD_BITS 32  // or: #define WORD_BITS (8 * sizeof(BN_ULONG))

// Helper function to get the index of the MSB within a single word
__device__ int get_msb_index(BN_ULONG word) {
    // This is a simple example using a linear scan; this can be made more efficient, for example,
    // by using the built-in __clz() or similar instructions specific to your architecture.
    for (int i = WORD_BITS - 1; i >= 0; --i) {
        if ((word >> i) & 1) {
            return i;
        }
    }
    return -1;  // if the word is zero, return -1 or another error indicator
}

__device__ int bn_get_top_bit(const BIGNUM *bn) {
    // Start scanning from the most significant word
    for (int i = bn->top - 1; i >= 0; --i) {
        int msb_index = get_msb_index(bn->d[i]);
        if (msb_index != -1) {  // If a bit is set in this word
            return i * WORD_BITS + msb_index;  // Return the global index of the MSB
        }
    }
    // If no bit is set in any word, this represents the number zero, and there is no MSB.
    return -1;  // The number is zero, so return -1 or another error indicator
}

__device__ void bn_divide(BIGNUM *quotient, BIGNUM *remainder, BIGNUM *dividend, BIGNUM *divisor) {
    // Initialize the quotient and remainder
    // bn_zero(quotient);
    // bn_zero(remainder);
    printf(" ++ bn_divide ++\n");
    init_zero(quotient, MAX_BIGNUM_WORDS);
    init_zero(remainder, MAX_BIGNUM_WORDS);

    // Copy of the dividend which will be reduced as division proceeds
    BIGNUM temp_dividend;
    init_zero(&temp_dividend, MAX_BIGNUM_WORDS);
    bn_copy(&temp_dividend, dividend); // You might need to ensure proper memory allocation for this copy
    
    // Initialize a temporary variable for subtracted values
    BIGNUM temp_subtract;
    // bn_zero(&temp_subtract);
    init_zero(&temp_subtract, MAX_BIGNUM_WORDS);

    // We need a BIGNUM for 'one' to increment the quotient for each subtraction, assuming we have such function
    BIGNUM one;
    init_zero(&one, MAX_BIGNUM_WORDS);
    bn_set_word(&one, 1);
    printf(" ## bn_divide ##\n");
    return ;
    

    // Long division algorithm
    while (bn_cmp(&temp_dividend, divisor) >= 0) { // As long as the dividend is greater than or equal to the divisor
        int shift_amount = bn_get_top_bit(&temp_dividend) - bn_get_top_bit(divisor); // calculate needed shift to align most significant bits
        BIGNUM shifted_divisor;
        init_zero(&shifted_divisor, MAX_BIGNUM_WORDS);
        bn_lshift_res(&shifted_divisor, divisor, shift_amount); // shift the divisor to the left to align with high bit of dividend
        
        // subtract the shifted divisor from the dividend until no longer possible
        while (bn_cmp(&temp_dividend, &shifted_divisor) >= 0) {
            bn_subtract(&temp_dividend, &temp_dividend, &shifted_divisor);
            BIGNUM shifted_one;
            init_zero(&shifted_one, MAX_BIGNUM_WORDS);
            bn_lshift_res(&shifted_one, &one, shift_amount); // the part of the quotient we will increment by corresponds to our shift
            bn_add(quotient, quotient, &shifted_one);
        }
        // Continue division until condition is no longer satisfied
    }

    // What remains in temp_dividend at this point is the remainder
    bn_copy(remainder, &temp_dividend);

    // Any necessary cleanup of BIGNUMs would be performed here
    // Make sure to handle any dynamic memory you may have allocated within this function
    printf(" -- bn_divide --\n");
}

__device__ void bn_mod_inverse_fixed(BIGNUM *result, BIGNUM *a, BIGNUM *modulus) {
    
    // Allocate and initialize working variables
    BIGNUM u, v, inv, u1, u3, v1, v3, t1, t3, q;
    // Initialization of these BIGNUMs with proper handling for the CUDA environment is required
    // Zero-initialize all BIGNUMs: u, v, inv, u1, u3, v1, v3, t1, t3, q
    
    /*bn_zero(&u); bn_zero(&v); bn_zero(&inv); 
    bn_zero(&u1); bn_zero(&u3); 
    bn_zero(&v1); bn_zero(&v3); 
    bn_zero(&t1); bn_zero(&t3); 
    bn_zero(&q);*/
    init_zero(&u, MAX_BIGNUM_WORDS);
    init_zero(&v, MAX_BIGNUM_WORDS);
    init_zero(&inv, MAX_BIGNUM_WORDS);
    init_zero(&u1, MAX_BIGNUM_WORDS);
    init_zero(&u3, MAX_BIGNUM_WORDS);
    init_zero(&v1, MAX_BIGNUM_WORDS);
    init_zero(&v3, MAX_BIGNUM_WORDS);
    init_zero(&t1, MAX_BIGNUM_WORDS);
    init_zero(&t3, MAX_BIGNUM_WORDS);
    init_zero(&q, MAX_BIGNUM_WORDS);
    
    // Set initial values: u1 = 1, u = a, v1 = 0, v = modulus
    bn_set_word(&u1, 1); 
    
    bn_copy(&u, a); 
    // bn_set_word(&v1, 0); -- v1 is already zero-initialized
    bn_copy(&v, modulus);
    
    // The algorithm proceeds to iteratively find the modular inverse
    while (!bn_is_zero(&u)) { // While u is not zero
        
        bn_divide(&q, &u3, &v, &u); // Divide v by u to get quotient (q) and remainder (u3)
        printf(" ## bn_mod_inverse TEST ##\n");
        bn_mul(&t3, &q, &v1); // t3 = q * v1
        bn_subtract(&t1, &u1, &t3); // t1 = u1 - t3

        // Shift: (u1, u) <- (v1, v), (v1, v) <- (t1, u3)
        bn_copy(&u1, &v1); bn_copy(&u, &v);
        bn_copy(&v1, &t1); bn_copy(&v, &u3);
    }
    
    // Ensure the result is non-negative
    if (bn_is_negative(&v1)) {
        bn_add(&inv, &v1, modulus);
    } else {
        bn_copy(&inv, &v1);
    }

    // Copy the result to the output parameter
    bn_copy(result, &inv);

}

__device__ void bn_mod_inverse(BIGNUM *result, BIGNUM *a, BIGNUM *modulus) {
    printf(" ## bn_mod_inverse ##\n");
    // Allocate and initialize working variables
    BIGNUM u, v, inv, u1, u3, v1, v3, t1, t3, q;
    // Initialization of these BIGNUMs with proper handling for the CUDA environment is required
    // Zero-initialize all BIGNUMs: u, v, inv, u1, u3, v1, v3, t1, t3, q
    
    /*bn_zero(&u); bn_zero(&v); bn_zero(&inv); 
    bn_zero(&u1); bn_zero(&u3); 
    bn_zero(&v1); bn_zero(&v3); 
    bn_zero(&t1); bn_zero(&t3); 
    bn_zero(&q);*/
    init_zero(&u, MAX_BIGNUM_WORDS);
    init_zero(&v, MAX_BIGNUM_WORDS);
    init_zero(&inv, MAX_BIGNUM_WORDS);
    init_zero(&u1, MAX_BIGNUM_WORDS);
    init_zero(&u3, MAX_BIGNUM_WORDS);
    init_zero(&v1, MAX_BIGNUM_WORDS);
    init_zero(&v3, MAX_BIGNUM_WORDS);
    init_zero(&t1, MAX_BIGNUM_WORDS);
    init_zero(&t3, MAX_BIGNUM_WORDS);
    init_zero(&q, MAX_BIGNUM_WORDS);
    
    // Set initial values: u1 = 1, u = a, v1 = 0, v = modulus
    bn_set_word(&u1, 1); 
    bn_copy(&u, a); 
    // bn_set_word(&v1, 0); -- v1 is already zero-initialized
    bn_copy(&v, modulus);

    // The algorithm proceeds to iteratively find the modular inverse
    while (!bn_is_zero(&u)) { // While u is not zero
        bn_divide(&q, &u3, &v, &u); // Divide v by u to get quotient (q) and remainder (u3)
        bn_mul(&t3, &q, &v1); // t3 = q * v1
        bn_subtract(&t1, &u1, &t3); // t1 = u1 - t3

        // Shift: (u1, u) <- (v1, v), (v1, v) <- (t1, u3)
        bn_copy(&u1, &v1); bn_copy(&u, &v);
        bn_copy(&v1, &t1); bn_copy(&v, &u3);
    }

    // Ensure the result is non-negative
    if (bn_is_negative(&v1)) {
        bn_add(&inv, &v1, modulus);
    } else {
        bn_copy(&inv, &v1);
    }

    // Copy the result to the output parameter
    bn_copy(result, &inv);

    // Implementation might include clean-up code for all BIGNUM variables 
    // especially if the BIGNUM structure requires deallocation of any allocated memory
}

// CUDA point_add function, based on gmp implementation
__device__ void point_add(
    EC_POINT *result, 
    EC_POINT *p1, 
    EC_POINT *p2, 
    BIGNUM *p, 
    BIGNUM *a
    ) {    // Handle the point at infinity cases
    //printf("A # Result x.d: %f, y.d: %f\n", result->x.d, result->y.d);
    bn_print("point_add init result.x: ", &result->x);
    bn_print("point_add init result.y: ", &result->y);
    bn_print("p1.x: ", &p1->x);
    bn_print("p1.y: ", &p1->y);
    bn_print("p2.x: ", &p2->x);
    bn_print("p2.y: ", &p2->y);
    // bn_print("A result: ", &result.x);
    if (point_is_at_infinity(p1)) {
        printf("point_is_at_infinity(p1)\n");
        //printf("0 # Result x.d: %f, y.d: %f\n", result->x.d, result->y.d);
        //printf("0 # p2 x.d: %f, y.d: %f\n", p2->x.d, p2->y.d);        
        copy_point(result, p2);
        printf("1 # Result x.d: %f, y.d: %f\n", result->x.d, result->y.d);
        return;
    }
    if (point_is_at_infinity(p2)) {
        printf("point_is_at_infinity(p2)\n");
        copy_point(result, p1);
        // printf("copying p1 to result success\n");
        return;
    }

    // Initialize temporary BIGNUMs for calculation
    BIGNUM s, x3, y3, tmp1, tmp2;
    init_zero(&s, MAX_BIGNUM_WORDS);
    init_zero(&x3, MAX_BIGNUM_WORDS);
    init_zero(&y3, MAX_BIGNUM_WORDS);
    init_zero(&tmp1, MAX_BIGNUM_WORDS);
    init_zero(&tmp2, MAX_BIGNUM_WORDS);
    // ... initialization code for BIGNUMs ...
    
    // Case 1: p1.x == p2.x && p1.y != p2.y
    /*if (bn_cmp(&p1->x, &p2->x) == 0 && bn_cmp(&p1->y, &p2->y) != 0) {
        printf("bn_cmp(&p1->x, &p2->x) == 0 && bn_cmp(&p1->y, &p2->y) != 0\n");
        set_point_at_infinity(result);
        return;
    }*/
    if (bn_cmp(&p1->x, &p2->x) == 0 && bn_cmp(&p1->y, &p2->y) == 0) {
        printf("Point Doubling\n");

        // Start point doubling calculation
        // Slope calculation: s = (3 * p1.x^2 + a) / (2 * p1.y)
        // print MAX_BIGNUM_WORDS
        printf("MAX_BIGNUM_WORDS: %d\n", MAX_BIGNUM_WORDS);
        BIGNUM two; 
        /*BN_ULONG d[8];
        two.d = d;
        two.neg = 0;
        two.top = 0;
        two.dmax = MAX_BIGNUM_WORDS;
        two.flags = 0;*/
        // print two params
        // printf("two.top: %d, two.neg: %d\n", two.top, two.neg);        
        init_zero(&two, MAX_BIGNUM_WORDS);
        
        bn_set_word(&two, 2);
        
        bn_mul(&tmp1, &p1->x, &p1->x); // tmp1 = p1.x^2
        
        bn_set_word(&tmp2, 3);
        
        bn_mul(&tmp1, &tmp1, &tmp2);   // tmp1 = 3 * p1.x^2
        
        bn_add(&tmp1, &tmp1, a); // tmp1 = 3 * p1.x^2 + a
        
        bn_mul(&tmp2, &p1->y, &two);    // tmp2 = 2 * p1.y
        bn_mod(&tmp1, p, &tmp1);        // tmp1 = tmp1 mod p
        
        bn_mod(&tmp2, p, &tmp2);        // tmp2 = tmp2 mod p
        
        bn_print("tmp2: ", &tmp2);
        bn_print("p: ", p);
        bn_mod_inverse_fixed(&tmp2, p, &tmp2);// tmp2 = (2 * p1.y)^-1 mod p
        printf("== pd ==\n");/*
        bn_mul(&s, &tmp1, &tmp2);       // s = (3 * p1.x^2 + a) / (2 * p1.y) mod p
        bn_mod(&s, p, &s);
        
        // x3 and y3 calculation:
        bn_mul(&x3, &s, &s);             // x3 = s^2
        bn_sub(&x3, &x3, &p1->x);        
        bn_sub(&x3, &x3, &p1->x);        // x3 = s^2 - 2 * p1.x
        bn_mod(&x3, p, &x3);             // x3 = x3 mod p

        bn_sub(&y3, &p1->x, &x3);        
        bn_mul(&y3, &s, &y3);            // y3 = s * (p1.x - x3)
        bn_sub(&y3, &y3, &p1->y);        // y3 = y3 - p1.y
        bn_mod(&y3, p, &y3);             // y3 = y3 mod p*/
    } else if (bn_cmp(&p1->x, &p2->x) == 0 && bn_cmp(&p1->y, &p2->y) != 0) {
        printf("The points are inverses to one another, returning infinity.\n");
        set_point_at_infinity(result);
        return;
    }

    // Case 2: p1.x != p2.x
    if (bn_cmp(&p1->x, &p2->x) != 0) {
        printf("bn_cmp(&p1->x, &p2->x) != 0\n");
        // Full point addition formula
        bn_sub(&tmp1, &p2->y, &p1->y);
        bn_sub(&tmp2, &p2->x, &p1->x);
        bn_mod(&tmp1, p, &tmp1);
        bn_mod(&tmp2, p, &tmp2);
        bn_mod_inverse(&tmp2, p, &tmp2); // Compute modular inverse
        bn_mul(&s, &tmp1, &tmp2);
        bn_mod(&s, p, &s);

        // ... continue with the point calculation using the BIGNUM operations ...
    } else {
        printf("bn_cmp(&p1->x, &p2->x) == 0\n");
        // Case 3: p1.x == p2.x
        // Point doubling formula
        // ... calculation code for doubling ...

        // Slope calculation:
        // s = (3 * p1.x^2 + a) / (2 * p1.y)

        // x3 and y3 calculation:
        // x3 = s^2 - 2 * p1.x
        // y3 = s * (p1.x - x3) - p1.y
    }

    // Assign the computed coordinates to the result
    //Print result->x.d and result->y.d
    printf("B # Result x.d: %f, y.d: %f\n", result->x.d, result->y.d);
    set_bn(&result->x, &x3);
    set_bn(&result->y, &y3);
    printf("C # Result x.d: %f, y.d: %f\n", result->x.d, result->y.d);

    // Free the temporary variables
    // ... free BIGNUMs ...
}

/*__device__ void point_add_v2(
    EC_POINT *result, 
    const EC_POINT *P, 
    const EC_POINT *Q, 
    const BIGNUM *curve_prime, 
    const BIGNUM *curve_a
) {
    // Handle the point at infinity cases
    if (point_is_at_infinity(P)) {
        copy_point(result, Q);
        return;
    }
    if (point_is_at_infinity(Q)) {
        copy_point(result, P);
        return;
    }
    // ... [other logic before this point] ...

    // Case 3: P.x == Q.x (i.e., point doubling)
    if (bn_cmp(&P->x, &Q->x) == 0) {
        // Perform point doubling calculation...
        BIGNUM s, temp1, temp2;

        // Calculating s as in Python's: s = (3 * P.x^2 + curve_a) * pow(2 * P.y, -1, p)
        // NOTE: You would need to implement functions for squaring, modular inversion,
        //       BIGNUM multiplication/addition, etc.

        // For example:
        bn_square(&temp1, &P->x);        // temp1 = P.x^2
        bn_mul_word(&temp1, &temp1, 3);  // temp1 = 3 * P.x^2
        bn_add(&temp1, &temp1, curve_a); // temp1 = 3 * P.x^2 + curve_a
        bn_lshift(&temp2, &P->y, 1);    // temp2 = 2 * P.y

        // Calculate the modular inverse of 2*P.y, storing in temp2
        bn_mod_inverse(&temp2, &temp2, curve_prime);

        // Multiply the inverse by (3 * P.x^2 + curve_a), storing result in s
        bn_mul(&s, &temp1, &temp2);
        bn_mod(&s, &s, curve_prime);

        // Add the debug print after calculating s
        bn_print("p: ", curve_prime);
        bn_print("s: ", &s);

        // ... [rest of the code to compute the resulting x and y using s] ...
    }
    // ... [rest of the function] ...
}*/

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

//__device__ EC_POINT ec_point_scalar_mul(EC_POINT *point, BIGNUM *scalar, BIGNUM *curve_order) {
__device__ EC_POINT ec_point_scalar_mul(
    EC_POINT *point, 
    BIGNUM *scalar, 
    BIGNUM *curve_prime, 
    BIGNUM *curve_a
    ) {
    EC_POINT current = *point;                       // This initializes the current point with the input point
    EC_POINT result;                                 // Initialize the result variable, which accumulates the result
    init_point_at_infinity(&result);                 // Initialize it to the point at infinity

    // Convert scalar BIGNUM to an array of integers that's easy to iterate bit-wise
    unsigned int bits[256];                          // Assuming a 256-bit scalar
    bignum_to_bit_array(scalar, bits);               // You will need to implement bignum_to_bit_array()

    // debug_printf("coef hex: %s\n", bignum_to_hex(scalar)); // Convert BIGNUM to hex string for printing
    bn_print("coef: ", scalar);  
    
    int debug_counter = 1;

    for (int i = 0; i < 256; i++) {                 // Assuming 256-bit scalars
        if (i<debug_counter) {
            // debug_printf("0 x: %s\n", bignum_to_hex(&current.x));
            bn_print("0 current.x: ", &current.x);
            // debug_printf("0 y: %s\n", bignum_to_hex(&current.y));
            bn_print("0 current.y: ", &current.y);
        }

        if (bits[i]) {// If the i-th bit is set
            
            // if (i<debug_counter) printf("# 0\n");
            // point_add(&result, &current, &result);  // Add current to the result
            // point_add(&result, &current, &result, &field_order);  // Add current to the result
            //point_add(&result, &current, &result, curve_order);  // Add current to the result
            point_add(&result, &current, &result, curve_prime, curve_a);  // Add current to the result
             // if (i<debug_counter) printf("# b\n");
            // debug_printf("1 x: %s\n", bignum_to_hex(&result.x));
             if (i<debug_counter) bn_print("1 result.x: ", &result.x);
            // debug_printf("1 y: %s\n", bignum_to_hex(&result.y));
             if (i<debug_counter) bn_print("1 result.y: ", &result.y);

        }
        if (i<debug_counter) debug_printf("# c\n");

        //point_double(&current, &current);           // Double current
        // point_double(&current, &current, &field_order);  // Double current and store the result in current
        // point_double(&current, &current, curve_order);

        // We don't need to double the point. We can just add it to itself.
        //point_add(&current, &current, &current, curve_order);
        point_add(&current, &current, &current, curve_prime, curve_a);  // Double current by adding to itself

        // debug_printf("2 x: %s\n", bignum_to_hex(&current.x));
        if (i<debug_counter) bn_print("2 current.x: ", &current.x);
        // debug_printf("2 y: %s\n", bignum_to_hex(&current.y));
        if (i<debug_counter) bn_print("2 current.y: ", &current.y);
        break; // TODO: remove this
    }

    // debug_printf("Final x: %s\n", bignum_to_hex(&result.x));
    bn_print("Final x: ", &result.x);
    // debug_printf("Final y: %s\n", bignum_to_hex(&result.y));
    bn_print("Final y: ", &result.y);

    return result;
}
// Public key derivation --

__global__ void testKernel() {

    // BN_CTX *ctx = BN_CTX_new();

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
    EC_POINT publicKey = ec_point_scalar_mul(&G, &newKey, &CURVE_P, &CURVE_A);
    // ec_point_scalar_mul / point_add / mod_mul / bn_mod <= Issue

    // Print public key
    printf("Public key:\n");
    bn_print("Public key x: ", &publicKey.x);
    bn_print("Public key y: ", &publicKey.y);


    // BN_CTX_free(ctx);

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