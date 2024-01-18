#include "bn.h"
#include <assert.h>
#define debug_print false
#define BN_MASK2 0xffffffff;
#define BN_ULONG_NUM_BITS 64
#define MAX_BIGNUM_WORDS 4     // For 256-bit numbers
#define MAX_BIGNUM_SIZE 6     // Allow room for temp calculations

typedef struct bignum_st {
  BN_ULONG *d;
  int top;
  int dmax;
  int neg;
  int flags;
} BIGNUM;

__device__ void bn_add(BIGNUM *result, BIGNUM *a, BIGNUM *b);

__device__ void bn_print(const char* msg, BIGNUM* a) {
    printf("%s", msg);
    if (a->top == 0) {
        printf("0\n");  // Handle the case where BIGNUM is zero
        return;
    }
    if (a->neg) {
        printf("-");  // Handle the case where BIGNUM is negative
    }
    for (int i = a->top - 1; i >= 0; i--) {
        // Print words up to top - 1 with appropriate formatting
        if (i == a->top - 1) {
            printf("%llx", a->d[i]);
        } else {
            printf(" %016llx", a->d[i]);
        }
    }
    printf("\n");
}

__device__ int find_top(BIGNUM *bn, int max_words) {
    for (int i = max_words - 1; i >= 0; i--) {
        // printf(">> find_top [%d]: %llx", i, bn->d[i]);
        // bn_print("", bn);
        if (bn->d[i] != 0) {
            // printf(">> find_top returning %d\n", i + 1);
            return i + 1;  // The top index is the index of the last non-zero word plus one
        }
    }
    // printf(">> find_top returning 0\n");
    return 0; // If all words are zero, the top is 0
}

__device__ void debug_printf(const char *fmt, ...) {
    if (debug_print) {
        printf(fmt);
    }
}

__device__ BN_ULONG bn_sub_words(BN_ULONG* r, BN_ULONG* a, BN_ULONG* b, int n) {
  
  BN_ULONG borrow = 0;
  for (int i = 0; i < n; i++) {
    BN_ULONG t1 = a[i];
    BN_ULONG t2 = b[i];
    BN_ULONG w = (t1 - borrow) - t2;
    borrow = (w > t1); // handle borrow
    r[i] = w; 
  }

  return borrow;
}

__device__ void reverse(BN_ULONG* d, int n) {
  BN_ULONG tmp;
  for(int i=0; i < n/2; i++) {
    tmp = d[i];
    d[i] = d[n - i - 1];
    d[n - i - 1] = tmp; 
  }
}

__device__ void init_zero(BIGNUM *bn, int capacity) {
    bn->d = new BN_ULONG[capacity]; // Dynamically allocate the required number of words.
    for (int i = 0; i < capacity; i++) {
        bn->d[i] = 0;
    }

    // top is used for representing the actual size of the 
    // significant part of the number for calculation purposes.
    bn->top = 0; // There are no significant digits when all words are zero.

    bn->neg = 0;
    
    // dmax is used to manage the memory allocation and ensure you 
    // do not access out-of-bounds memory.
    bn->dmax = capacity; // Make sure to track the capacity in dmax.
}

__device__ void init_one(BIGNUM *bn, int capacity) {
    init_zero(bn, capacity); // Initialize the BIGNUM to zero first
    bn->d[0] = 1;           // Set the least significant word to 1
    bn->top = (capacity > 0) ? 1 : 0; // There is one significant digit if capacity allows
}

__device__ int bn_cmp(BIGNUM* a, BIGNUM* b) {
    // bn_cmp logic:
    //  1 when a is larger
    // -1 when b is larger
    //  0 wneh a and b are equal

  // Skip leading zeroes and find the actual top for a
  int a_top = a->top - 1;
  while (a_top >= 0 && a->d[a_top] == 0) a_top--;

  // Skip leading zeroes and find the actual top for b
  int b_top = b->top - 1;
  while (b_top >= 0 && b->d[b_top] == 0) b_top--;

  // Compare signs
  if (a->neg && !b->neg) return -1; // a is negative, b is positive: a < b
  if (!a->neg && b->neg) return 1;  // a is positive, b is negative: a > b

  // If both numbers are negative, we need to reverse the comparison of their magnitudes
  int sign_factor = (a->neg && b->neg) ? -1 : 1;

  // Now, use the actual tops for comparison
  if (a_top > b_top) return sign_factor * 1; // Consider sign for magnitude comparison
  if (a_top < b_top) return sign_factor * -1;

  // Both numbers have the same number of significant digits, so compare them starting from the most significant digit
  for (int i = a_top; i >= 0; i--) {
    if (a->d[i] > b->d[i]) return sign_factor * 1; // a is larger (or smaller if both are negative)
    if (a->d[i] < b->d[i]) return sign_factor * -1; // b is larger (or smaller if both are negative)
  }
  return 0; // Numbers are equal
}

__device__ int bn_cmp_v0(BIGNUM* a, BIGNUM* b) {
  // Skip leading zeroes and find the actual top for a
  int a_top = a->top - 1;
  while (a_top >= 0 && a->d[a_top] == 0) a_top--;

  // Skip leading zeroes and find the actual top for b
  int b_top = b->top - 1;
  while (b_top >= 0 && b->d[b_top] == 0) b_top--;

  // Now, use the actual tops for comparison
  if (a_top > b_top) return 1;
  if (a_top < b_top) return -1;

  // Both numbers have the same number of significant digits, so compare them starting from the most significant
  for (int i = a_top; i >= 0; i--) {
    if (a->d[i] > b->d[i]) return 1; // a is larger
    if (a->d[i] < b->d[i]) return -1; // b is larger
  }
  return 0; // Numbers are equal
}

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

__device__ void absolute_add(BIGNUM *result, const BIGNUM *a, const BIGNUM *b) {
    // Determine the maximum size to iterate over
    int max_top = max(a->top, b->top);
    BN_ULONG carry = 0;

    // Initialize result
    for (int i = 0; i <= max_top; ++i) {
        result->d[i] = 0;
    }
    result->top = max_top;

    for (int i = 0; i <= max_top; ++i) {
        // Extract current words or zero if one bignum is shorter
        BN_ULONG ai = (i < a->top) ? a->d[i] : 0;
        BN_ULONG bi = (i < b->top) ? b->d[i] : 0;

        // Calculate sum and carry
        BN_ULONG sum = ai + bi + carry;

        // Store result
        result->d[i] = sum & ((1ULL << BN_ULONG_NUM_BITS) - 1); // Full sum with carry included, mask with the appropriate number of bits

        // Calculate carry, respecting the full width of BN_ULONG
        carry = (sum < ai) || (carry > 0 && sum == ai) ? 1 : 0;
    }

    // Handle carry out, expand result if necessary
    if (carry > 0) {
        if (result->top < MAX_BIGNUM_WORDS - 1) {
            result->d[result->top] = carry; // Assign carry to the new word
            result->top++;
        } else {
            // Handle error: Result BIGNUM doesn't have space for an additional word.
            // This should potentially be reported back to the caller.
        }
    }

    // Find the real top after addition (no leading zeroes)
    result->top = find_top(result, MAX_BIGNUM_WORDS);
}

__device__ void absolute_subtract(BIGNUM *result, const BIGNUM *a, const BIGNUM *b) {
    // This function assumes both 'a' and 'b' are positive.
    // It subtracts the absolute values |b| from |a|, where |a| >= |b|.
    // If |a| < |b|, it's the caller's responsibility to set result->neg appropriately.

    int max_top = max(a->top, b->top);
    BN_ULONG borrow = 0;
    result->top = max_top;

    for (int i = 0; i < max_top; ++i) {
        BN_ULONG ai = (i < a->top) ? a->d[i] : 0;
        BN_ULONG bi = (i < b->top) ? b->d[i] : 0;

        // Calculate the word subtraction with borrow
        BN_ULONG sub = ai - bi - borrow;
        result->d[i] = sub;
        
        // Update borrow which is 1 if subtraction underflowed, 0 otherwise.
        borrow = (ai < bi + borrow) ? 1 : 0;
    }

    // If there's a borrow left at the last word, this means |a| was less than |b|. Set top to 0 to denote invalid result.
    if (borrow != 0) {
        result->top = 0;  // Set to 0 to denote invalid bignum
        printf("Error: Underflow in subtraction, result is invalid.\n");
    }
}

__device__ void bn_subtract(BIGNUM *result, BIGNUM *a, BIGNUM *b) {
    // Determine the real sign of the result based on the signs of a and b.
    if (a->neg != b->neg) {
        // If one is negative and the other is positive, it's essentially an addition.
        result->neg = a->neg;  // The sign will be the same as the sign of 'a'.
        // Should perform an addition of magnitudes here because b is negative.
        absolute_add(result, a, b); // This line should be added to perform the absolute value addition.
        return;
    } else {
        // Else, signs are same, and it's a subtraction.
        // The result will have the sign of 'a' if |a| >= |b|, otherwise, it will
        // be the opposite of 'a' sign because |a| < |b|.
        result->neg = (bn_cmp(a, b) >= 0) ? a->neg : !a->neg;
    }

    // Perform the absolute subtraction without altering 'a' and 'b'.
    // The function 'absolute_subtract' needs to be implemented as subtraction of |a| and |b|.
    absolute_subtract(result, a, b);

    // Find the top of the resulting bignum to remove leading zeros
    find_top(result, MAX_BIGNUM_WORDS);

    // If 'a' and 'b' were of different signs, we already set result->neg accordingly.
    // We are dealing with the scenario where |a| - |b| or |b| - |a| is performed.
}

__device__ void bn_add(BIGNUM *result, BIGNUM *a, BIGNUM *b) {
    if (a->neg != b->neg) {
        // Handle the case where a and b have different signs
        // This is a subtraction operation
        bn_subtract(result, a, b);
        return;
    }
    // Determine the maximum size to iterate over
    int max_top = max(a->top, b->top)+1;
    BN_ULONG carry = 0;

    // Initialize result
    for (int i = 0; i < max_top; ++i) { result->d[i] = 0; }
    result->top = max_top;
    
    for (int i = 0; i < max_top; ++i) {
        // Extract current words or zero if one bignum is shorter
        BN_ULONG ai = (i < a->top) ? a->d[i] : 0;
        BN_ULONG bi = (i < b->top) ? b->d[i] : 0;
        
        // Calculate sum and carry
        BN_ULONG sum = ai + bi + carry;

        // Store result
        result->d[i] = sum; // Full sum with carry included

        // Calculate carry, respecting the full width of BN_ULONG
        carry = (sum < ai) || (carry > 0 && sum == ai) ? 1 : 0;
    }
    
    // Handle carry out, expand result if necessary
    if (carry > 0) {
        if (result->top < MAX_BIGNUM_WORDS) {
            result->d[result->top] = carry; // Assign carry to the new word
            result->top++;
        } else {
            // Handle error: Result BIGNUM doesn't have space for an additional word.
            // This should potentially be reported back to the caller.
        }
    }
    result->top = find_top(result, MAX_BIGNUM_WORDS);
    // Define the neg flag depends on bn_cmp, a and b neg
    // Both numbers are negative
    if (a->neg && b->neg) {
        result->neg = 1;
    }
    // 'a' is negative, 'b' is positive
    else if (a->neg && !b->neg) {
        result->neg = (bn_cmp(a, b) > 0) ? 1 : 0;
    }
    // 'a' is positive, 'b' is negative
    else if (!a->neg && b->neg) {
        result->neg = (bn_cmp(a, b) < 0) ? 1 : 0;
    }
    // Both numbers are positive
    else {
        result->neg = 0;
    }

}

__device__ void bn_mod(BIGNUM* r, BIGNUM* m, BIGNUM* d) {
    //debug_printf("bn_mod 0\n");
    printf("bn_mod 0\n");
    // Copy m to r
    for (int i = 0; i < m->top; i++) {
        debug_printf("bn_mod: 0.%d r_top: %d m_top: %d\n", i, r->top, m->top);
        r->d[i] = m->d[i];
    }
    printf("bn_mod 1\n");
    r->top = m->top;
    r->neg = 0;
    printf("bn_mod 2\n");

    // Ensure r has enough space to cover subtraction up to d->top
    for (int i = m->top; i < d->top; i++) {
        r->d[i] = 0; // Zero out any remaining indices
    }
    printf("bn_mod 3\n");
    if (d->top > r->top) {
        r->top = d->top; // Increase the top to match d, if necessary
    }
    printf("bn_mod 4\n");

    // Keep subtracting d from r until r < d
    while (true) {
        // Check if r < d or r == d
        int compare = bn_cmp(r, d); // Need to implement bn_cmp to compare BIGNUMs
        //printf("bn_mod >> x\n");
        //printf("bn_mod >> compare: %d\n", compare);
        if (compare < 0) {
            // r < d, we are done
            //printf("bn_mod >> y\n");
            break;
        } else if (compare == 0) {
            // r == d, set r to 0 and we are done
            /*printf("bn_mod >> z\n");
            printf("bn_mod >> r_top: %d\n", r->top);
            printf("bn_mod >> r_neg: %d\n", r->neg);
            printf("bn_mod >> r_dmax: %d\n", r->dmax);
            printf("bn_mod >> r_flags: %d\n", r->flags);*/
            init_zero(r, MAX_BIGNUM_SIZE);
            // init_zero(r, MAX_BIGNUM_WORDS);
            //printf("bn_mod >> 0\n");
            break;
        }

        // r > d, so subtract d from r
        int borrow = 0;
        for (int i = 0; i < r->top; i++) {
            printf(">> bn_mod: 1.%d r_top: %d d_top: %d\n", i, r->top, d->top);
            long long res = (long long)r->d[i] - (long long)((i < d->top) ? d->d[i] : 0) - borrow;
            borrow = (res < 0) ? 1 : 0;
            if (res < 0) {
                res += (1LL << 32); // Assuming each BN_ULONG is 32 bits
            }
            r->d[i] = (BN_ULONG)res;
        }

        // Additional condition to ensure r->top shrinks if top words are zero.
        while (r->top > 0 && r->d[r->top - 1] == 0) {
            --r->top;
        }
    }
    printf("bn_mod end\n");
}

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

__device__ void bn_sub_v2(BIGNUM *a, BIGNUM *b, BIGNUM *r) {
    printf("++ bn_sub ++\n");
    // get top of a and b
    a->top = find_top(a, MAX_BIGNUM_WORDS);
    b->top = find_top(b, MAX_BIGNUM_WORDS);

    bn_print(">> a: ", a);
    bn_print(">> b: ", b);

    int max = a->top > b->top ? a->top : b->top;
    BN_ULONG borrow = 0;
    printf("max: %d\n", max);
    
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

__device__ void bn_sub(BIGNUM *r, BIGNUM *a, BIGNUM *b) {
    printf("++ bn_sub ++\n");
    // get top of a and b
    a->top = find_top(a, MAX_BIGNUM_WORDS);
    b->top = find_top(b, MAX_BIGNUM_WORDS);

    bn_print(">> a: ", a);
    bn_print(">> b: ", b);

    int max = a->top > b->top ? a->top : b->top;
    BN_ULONG borrow = 0;
    printf("max: %d\n", max);
    
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

/*__device__ void bn_mul_v0(BIGNUM *a, BIGNUM *b, BIGNUM *product) {
    // Assuming all BIGNUMs are initialized and `d` arrays have enough allocated memory.
    
    // Initialize product to zero.
    for (int i = 0; i < product->dmax; i++) {
        product->d[i] = 0;
    }
    product->top = 0;

    // Multiply each digit of a by each digit of b, accumulate results in product
    for (int i = 0; i < a->top; i++) {
        BN_ULONG carry = 0;
        for (int j = 0; j < b->top || carry; j++) {
            // Calculate the full multiplication result (including carry)
            unsigned long long sum = (unsigned long long)product->d[i + j] + carry;
            
            // If we don't exceed b's digits, include the multiplication result
            if (j < b->top) {
                sum += (unsigned long long)a->d[i] * b->d[j];
            }
            
            product->d[i + j] = (BN_ULONG)sum; // Store the lower half of the result
            carry = (BN_ULONG)(sum >> BN_ULONG_NUM_BITS); // Shift right to get the upper half (carry)
        }

        // Make sure to check the next cell if a carry is present
        if (carry && (i + b->top + 1 > product->top)) {
            product->d[i + b->top] = carry;
            product->top = i + b->top + 1; // Include the extra cell used by carry
        } else if (i + b->top > product->top) {
            product->top = i + b->top; // Update top based on position
        }
    }

    // Now 'product' contains the product of 'a' and 'b', without modulo operation.
    // Perform a modulo operation here if necessary (modular reduction).
}*/
__device__ void bn_mul_v1_top_ok(BIGNUM *a, BIGNUM *b, BIGNUM *product) {
    // Initialize product to zero.
    for (int i = 0; i < product->dmax; i++) {
        product->d[i] = 0;
    }
    
    // Set product 'top' to 0 initially.
    product->top = 0;

    // Multiply each digit of a by each digit of b, accumulate results in product
    for (int i = 0; i < a->top; i++) {
        BN_ULONG carry = 0;
        int j = 0;
        for (j = 0; j < b->top; j++) {
            // Calculate the full multiplication result (including carry)
            unsigned long long sum = (unsigned long long)product->d[i + j] +
                                     (unsigned long long)a->d[i] * b->d[j] +
                                     carry;
            
            product->d[i + j] = (BN_ULONG)sum; // Store the lower part of the result
            carry = (BN_ULONG)(sum >> BN_ULONG_NUM_BITS); // Shift right to get the upper part (carry)
        }
        if (carry > 0) {
            product->d[i + j] = carry; // Store the last carry, if any
            product->top = i + j + 1; // Update 'top' to reflect the true size
        } else {
            product->top = i + j; // Update 'top' to reflect the true size
        }
    }

    // Sanitize the 'top' value to ensure it does not include any leading zero words.
    while (product->top > 0 && product->d[product->top - 1] == 0) {
        product->top--;
    }

    // Now 'product' contains the product of 'a' and 'b', without modulo operation.
}

__device__ void bn_mul_v2_bad(BIGNUM *a, BIGNUM *b, BIGNUM *product) {
    // Initialize the product to zero.
    for (int i = 0; i < a->top + b->top; i++) {
        product->d[i] = 0;
    }

    // Perform the multiplication and accumulate the results.
    for (int i = 0; i < a->top; i++) {
        BN_ULONG carry = 0;
        int j;
        for (j = 0; j < b->top; j++) {
            unsigned long long sum = (unsigned long long)product->d[i + j] +
                                     (unsigned long long)a->d[i] * (unsigned long long)b->d[j] +
                                     (unsigned long long)carry;
            product->d[i + j] = (BN_ULONG)(sum & 0xFFFFFFFFFFFFFFFFULL);  // Assume 64-bit words
            carry = (BN_ULONG)(sum >> BN_ULONG_NUM_BITS);
        }

        // If there is carry left at the end of the inner loop, it should be added to the next position
        product->d[i + j] = carry;
    }

    // Find the most significant non-zero word and update the 'top'
    for (int k = a->top + b->top - 1; k >= 0; k--) {
        if (product->d[k] != 0) {
            product->top = k + 1;
            break;
        }
    }

    // If after the multiplication the 'top' is zero, set 'top' to 1
    // because even with a zero product, there should be at least one word in length.
    if (product->top == 0) {
        product->top = 1;
    }
}

__device__ void bn_mul_v3_bad(BIGNUM *a, BIGNUM *b, BIGNUM *product) {
    // Initialize the product to zero.
    for (int i = 0; i < a->top + b->top; i++) {
        product->d[i] = 0;
    }

    // Perform the multiplication and accumulate the results.
    for (int i = 0; i < a->top; i++) {
        BN_ULONG carry = 0;
        int j;
        for (j = 0; j < b->top; j++) {
            unsigned long long sum = (unsigned long long)product->d[i + j] +
                                     (unsigned long long)a->d[i] * (unsigned long long)b->d[j] +
                                     (unsigned long long)carry;
            product->d[i + j] = (BN_ULONG)(sum & 0xFFFFFFFFFFFFFFFFULL);  // Assume 64-bit words
            carry = (BN_ULONG)(sum >> BN_ULONG_NUM_BITS);
        }
        product->d[i + j] = carry;  // Store the carry in the next word of the product.
    }

    // Set the top to reflect the actual size of the product.
    for (int k = a->top + b->top; k > 0; k--) {
        if (product->d[k - 1] != 0) {
            product->top = k;
            break;
        }
    }

    if (product->top == 0) {
        // Even a zero product should have a top of 1.
        product->top = 1;
    }
}

__device__ void bn_add_words(BN_ULONG *a, unsigned long long carry, int idx, int dmax) {
    // Since carry could be more than one word, propagate it if necessary.
    while (carry != 0 && idx < dmax) {
        unsigned long long sum = (unsigned long long) a[idx] + (carry & 0xFFFFFFFFFFFFFFFFULL);
        a[idx] = (BN_ULONG)(sum & 0xFFFFFFFFFFFFFFFFULL);
        carry = sum >> BN_ULONG_NUM_BITS;
        idx++;
    }
}

__device__ void bn_mul(BIGNUM *a, BIGNUM *b, BIGNUM *product) {
    // Print the input values.
    /*printf("a = %016llx\n", a->d[0]);
    printf("b = %016llx\n", b->d[0]);*/
    // Notify if a.top>1 or b.top>1
    if (a->top > 1) {
        printf("ATTENTION! bn_mul: a.top > 1\n");
    }
    if (b->top > 1) {
        printf("ATTENTION! bn_mul: b.top > 1\n");
    }

    // Set high parts to zero for single BN_ULONG multiplication
    unsigned long long alow = a->d[0], blow = b->d[0];  // Low 64 bits
    unsigned long long ahigh = 0, bhigh = 0;
    unsigned long long lolo, lohi, hilo, hihi; // partial products

    // Perform multiplication of the lower words.
    lolo = a->d[0] * b->d[0];
    lohi = __umul64hi(a->d[0], b->d[0]);

    // Since higher words are zero, these multiplications will also be zero.
    hihi = ahigh * bhigh; // would be a higher overflow part (not needed for single word each).
    hilo = ahigh * blow; // not needed for single word each

    // Print the partial products
    /*printf("lolo = %016llx\n", lolo);
    printf("lohi = %016llx\n", lohi);
    printf("hilo = %016llx\n", hilo); // will always be zero in this context
    printf("hihi = %016llx\n", hihi); // will always be zero in this context*/

    // Clear the product BIGNUM
    product->d[0] = product->d[1] = 0;
    product->top = 0;

    // Set the product's lower and higher words
    product->d[0] = lolo;
    product->d[1] = lohi + hilo; // As hilo and hihi are zero, no additional carry will be added.

    // Print the intermediate product result before considering overflow
    //printf("Intermediate product = %016llx %016llx\n", product->d[1], product->d[0]);

    // Check if there is any overflow beyond 128 bits (should not be in this context)
    if ((lohi + hilo) < lohi) {
        // This means carrying into another higher word would be necessary
        //printf("Carry overflow occurred! Need to handle additional word.\n");
        // Assuming there's space for another word
        unsigned long long carry = 1;
        int i = 2; //next index after 0,1
        while (carry != 0 && i < a->top + b->top) {
            unsigned long long sum = product->d[i] + carry;
            product->d[i] = sum;
            carry = sum < carry ? 1 : 0; // Carry continues if the sum is less than carried value
            i++;
        }
    }

    // Update the 'top' based on the product.
    product->top = (product->d[1] != 0) ? 2 : (product->d[0] != 0) ? 1 : 0;

    // Print the final product and 'top' value
    /*printf("Final product = %016llx %016llx\n", product->d[1], product->d[0]);
    printf("Final top = %d\n", product->top);*/
}

/*__device__ void bn_mul_multi_word_wrong(BIGNUM *a, BIGNUM *b, BIGNUM *product) {
    // Initialize the product
    for (int i = 0; i < a->top + b->top; i++) {
        product->d[i] = 0;
    }
    
    // Perform multiplication for each word of 'BIGNUM a' with each word of 'BIGNUM b'.
    for (int i = 0; i < a->top; i++) {
        unsigned long long carry = 0;
        for (int j = 0; j < b->top; j++) {
            // Multiply current words.
            unsigned long long product_ij = (unsigned long long)a->d[i] * b->d[j];
            
            // Add product to the current spot in the result, taking into account the carry.
            unsigned long long sum = product->d[i + j] + (BN_ULONG)product_ij + carry;
            
            // Set the current spot in the result.
            product->d[i + j] = (BN_ULONG)sum;
            
            // Calculate carry for the next iteration.
            carry = (product_ij >> 64) + (sum >> 64);
        }
        
        // Propagate remaining carry
        int k = i + b->top;
        while (carry > 0 && k < a->top + b->top) {
            unsigned long long sum = (unsigned long long)product->d[k] + (carry & 0xFFFFFFFFFFFFFFFFULL);
            product->d[k] = (BN_ULONG)sum; // Store lower 64 bits of the sum
            carry = sum >> 64;  // The carry for the next word will be the upper 64 bits
            k++;
        }
    }
    
    // Set top of the product correctly
    product->top = a->top + b->top;
    while (product->top > 0 && product->d[product->top - 1] == 0)
        product->top--; // Shrink the top value if the higher words are zero.
}*/

// Important Note: This function assumes that `product` has been allocated with enough space
// to hold at least two words (BN_ULONG values), as the result may require up to 128-bits of space.

// Your CUDA kernel and main() function code would remain the same,
// call bn_mul(a, b, product) just like before within your kernel.

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

__device__ void bn_lshift_deprecated(BIGNUM *a, int shift) {
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
        bn_lshift_deprecated(q, 1); // TODO: check do we need to update to non-deprecated version
        bn_lshift_deprecated(r, 1); // same here
        
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

__device__ bool bn_is_zero(BIGNUM *a) {
    for (int i = 0; i < a->top; ++i) {
        if (a->d[i] != 0) {
            return false;
        }
    }
    return true;
}

__device__ bool bn_is_one(BIGNUM *a) {
    // Assuming that BIGNUM stores the number in an array 'd' of integers
    // and 'top' indicates the number of chunks being used.
    // We also assume that 'd' is big-endian and 'top' is the index of the highest non-zero digit.
    
    // The number one would be represented with only the least significant digit being one
    // and all other digits being zero.
    if (a->top != 1) {  // If there are more than one digits in use, it cannot be one
        return false;
    }
    if (a->d[0] != 1) {  // The number one should only have the least significant digit set to one
        return false;
    }
    // Ensure that any other digits (if they exist in memory) are zero
    // This isn't strictly necessary if the 'top' index is always accurate
    // but is a good sanity check if there's any possibility of memory corruption or improper initialization.
    for (int i = 1; i < MAX_BIGNUM_WORDS; ++i) {
        if (a->d[i] != 0) {
            return false;
        }
    }
    return true;
}

__device__ int bn_is_negative(const BIGNUM *a) {
    // Assuming the neg field is defined and holds the sign (0 for non-negative, 1 for negative)
    return a->neg != 0;
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
    //printf("++ bn_lshift_res ++\n");
    if (shift <= 0) {
        // No shift or invalid shift count; copy input to output with no modifications.
        bn_copy(result, a);
        //printf("bn_lshift_res 0\n");
        return;
    }

    // Initialize result BIGNUM according to your BIGNUM structure definition
    // Make sure that result->d has enough space to hold the result

    // Perform the shift for each word from the least significant upwards.
    BN_ULONG carry = 0;
    for (int i = 0; i < a->top; ++i) {
        //printf("bn_lshift_res [%d]\n", i);
        // bn_print("a: ", a);        
        BN_ULONG new_carry = a->d[i] >> (BN_ULONG_NUM_BITS - shift); // Capture the bits that will be shifted out.
        //printf("new_carry: %llu\n", new_carry);
        result->d[i] = (a->d[i] << shift) | carry; // Shift current word and add bits from previous carry.
        //printf("result->d[i]: %llu\n", result->d[i]);
        carry = new_carry; // Update carry for the next iteration.
    }

    // Assign the carry to the new most significant word if needed.
    if (carry != 0) {
        //printf("bn_lshift_res 1\n");
        //bn_print("result 0: ", result);
        result->d[a->top] = carry; // Assign the carry to the new most significant word.
        //printf("result->d[a->top]: %llu\n", result->d[a->top]);
        result->top = a->top + 1;
        //printf("result->top: %d\n", result->top);
    } else {
        //printf("bn_lshift_res 2\n");
        //bn_print("result 1: ", result);
        result->top = a->top;
        //printf("result->top: %d\n", result->top);
    }

    // Initialize any remaining higher-order words to zero if necessary
    // This depends on the internals of your BIGNUM structure.
    for (int i = result->top; i < result->dmax; ++i) {
        result->d[i] = 0;
    }
    //printf("-- bn_lshift_res --\n");
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

__device__ int bn_get_top_bit(BIGNUM *bn) {
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

__device__ int bn_get_top_bit_word(BN_ULONG word) {
    if (word == 0) return -1; // Special case if the word is zero
    
    // Find the most significant bit (MSB) set
    int bit_index = 0;
    for (int i = BN_ULONG_NUM_BITS - 1; i >= 0; --i) {
        if (word & ((BN_ULONG)1 << i)) {
            bit_index = i;
            break;
        }
    }
    return bit_index;
}

__device__ void bn_normalize(BIGNUM *bn) {
    // Ensure that the top is properly set, not beyond the non-zero words
    while (bn->top > 0 && bn->d[bn->top - 1] == 0) {
        bn->top--;
    }
    // If all words are zero, then set top to -1 or 0 based on your convention
    if (bn->top == 0) {
        bn->top = -1;  // Use 0 if your convention is to start `top` from 0 for a non-zero bignum
    }
}

#define BN_ULONG_BITS (sizeof(BN_ULONG) * 8)

__device__ int get_msb_bit(BIGNUM *n) {
  for (int i = n->top - 1; i >= 0; i--) {
    BN_ULONG word = n->d[i]; 
    for (int j = BN_ULONG_BITS - 1; j >= 0; j--) {
      if (word & ((BN_ULONG)1 << j)) { 
        return (i * BN_ULONG_BITS) + j;
      }
    }
  }
  return -1; // All zero
}

__device__ void bn_rshift_one(BIGNUM *bn) {
    if (bn_is_zero(bn)) {
        return; // If the big number is zero, there's nothing to shift
    }

    BN_ULONG carry = 0;
    for (int i = bn->top - 1; i >= 0; --i) {
        // Take the current digit and the previous carry to create a composite
        BN_ULONG composite = (carry << (BN_ULONG_NUM_BITS - 1)) | (bn->d[i] >> 1);
        carry = bn->d[i] & 1; // Save the LSB before shifting as the next carry
        bn->d[i] = composite;
    }

    // If the most significant digit is now zero, update the `top` counter
    if (bn->top > 0 && bn->d[bn->top - 1] == 0) {
        bn->top--;
    }
}

__device__ void bn_divide(BIGNUM *quotient, BIGNUM *remainder, BIGNUM *dividend, BIGNUM *divisor) {
    // If divident top or divisor top is bigger than one, then notify
    if (dividend->top > 1) {
        printf("ATTENTION! bn_divide: dividend.top > 1\n");
    }
    if (divisor->top > 1) {
        printf("ATTENTION! bn_divide: divisor.top > 1\n");
    }
    //printf(" ++ bn_divide ++ \n");

    // Initialize quotient and remainder
    init_zero(quotient, MAX_BIGNUM_WORDS);
    init_zero(remainder, MAX_BIGNUM_WORDS);
    bn_copy(remainder, dividend);

    if (bn_is_zero(divisor)) {
        //printf("Division by zero!\n");
        return;
    }

    BIGNUM temp_divisor;
    init_zero(&temp_divisor, MAX_BIGNUM_WORDS);

    int word_shift, bit_shift;

    //while (bn_cmp(remainder, divisor) >= 0 && debug_count < 10) {
    while (bn_cmp(remainder, divisor) >= 0) {
        // Calculate needed shifts
        word_shift = remainder->top - divisor->top;
        bit_shift = get_msb_bit(remainder) - get_msb_bit(divisor);

        // Handle negative shift
        if (bit_shift < 0) {
            bit_shift += BN_ULONG_NUM_BITS;
            word_shift--;
        }

        // Print debug shifts
        //printf("Word shift: %d, Bit shift: %d\n", word_shift, bit_shift);

        // Shift divisor
        bn_lshift_res(&temp_divisor, divisor, bit_shift + (word_shift * BN_ULONG_NUM_BITS));

        // Print debug values
        /*bn_print("Shifted divisor", &temp_divisor);
        bn_print("Remainder", remainder);
        bn_print("Quotient ", quotient);*/

        // If the shifted divisor is greater, decrease shift
        if (bn_cmp(&temp_divisor, remainder) > 0) {
            bit_shift--;
            bn_rshift_one(&temp_divisor);
        }

        // Main division step
        bn_subtract(remainder, remainder, &temp_divisor);

        // Add the shift to quotient
        if (quotient->top < word_shift + 1) {
            quotient->top = word_shift + 1; // Update the number of digits
        }
        quotient->d[word_shift] |= ((BN_ULONG)1 << bit_shift);

        // Print debug values
        /*bn_print("After Subtraction - Shifted divisor", &temp_divisor);
        bn_print("After Subtraction - Remainder", remainder);
        bn_print("After Subtraction - Quotient ", quotient);*/
    }

    /*if (debug_count >= 10) {
        printf("Error: debug_count >= 10 in bn_divide.\n");
    }*/

    //printf(" -- bn_divide --\n");
}

__device__ void bn_abs(BIGNUM *result, BIGNUM *a) {
    // Assuming the BIGNUM structure includes an attribute to indicate the sign (e.g., 'sign')
    // Copy the number from a to result
    // In actual code, this would likely need to loop over each digit and copy them.
    for (int i = 0; i < a->top; ++i) {
        result->d[i] = a->d[i];
    }
    // Ensure result uses the same number of digits as 'a'
    result->top = a->top;

    // Set the sign of the result to be non-negative (0 for positive in many conventions)
    // result->sign = 0;
    result->neg = 0;
}

__device__ void bn_set_signed_word(BIGNUM *r, int64_t value) {
    // Clear any existing value in r.
    // Assuming MAX_BIGNUM_WORDS is defined and represents the maximum size of d[].
    for (int i = 0; i < MAX_BIGNUM_WORDS; ++i) {
        r->d[i] = 0;
    }

    // Set the sign in r. Assuming the sign is represented by a simple integer where
    // negative numbers have sign = -1 and non-negatives have sign = 0.
    // r->sign = (value < 0) ? -1 : 0;
    r->neg = (value < 0) ? -1 : 0;

    // Store the absolute value of the word in the least significant part of r.
    // Assuming the magnitude can fit in a single 'word' of the BIGNUM data structure.
    // Depending on how BIGNUM is structured, you might need to handle cases where
    // the magnitude of the integer does not fit into a single array element.
    r->d[0] = (value < 0) ? -value : value;

    // Set 'top' to reflect that we're now using the least significant word only.
    // Assuming 'top' is an index of the highest non-zero element.
    r->top = (value != 0) ? 1 : 0;
}

__device__ void bn_swap(BIGNUM *a, BIGNUM *b) {
    // Swap the dynamic parts
    // mp_ptr temp_d = a->d;
    BN_ULONG *temp_d = a->d;
    a->d = b->d;
    b->d = temp_d;
    
    // Swap the scalar components such as top, sign etc.
    int temp_top = a->top;
    a->top = b->top;
    b->top = temp_top;

    int temp_sign = a->neg;
    a->neg = b-> neg;
    b->neg = temp_sign;
    
    // ... Repeat for other scalar elements of BIGNUM as necessary
}

__device__ void bn_gcdext(BIGNUM *g, BIGNUM *s, BIGNUM *t, BIGNUM *a, BIGNUM *b_original) {
    printf("++ bn_gcdext ++\n");

    // Temporary BIGNUM for b, to avoid modifying the original b
    BIGNUM b_temp;
    init_zero(&b_temp, MAX_BIGNUM_WORDS);
    bn_copy(&b_temp, b_original); // Copy original b to temporary variable

    // Temporary BIGNUM variables for intermediate calculations
    BIGNUM prev_s, prev_t, quotient, temp;
    init_zero(&prev_s, MAX_BIGNUM_WORDS);
    init_zero(&prev_t, MAX_BIGNUM_WORDS);
    init_zero(&quotient, MAX_BIGNUM_WORDS);
    init_zero(&temp, MAX_BIGNUM_WORDS);
    
    // Initialize s and t coefficients for the extended GCD algorithm
    init_one(s, MAX_BIGNUM_WORDS);     // s = 1
    
    init_zero(&prev_s, MAX_BIGNUM_WORDS);  // prev_s = 0
    
    init_zero(t, MAX_BIGNUM_WORDS);    // t = 0
    printf("## bn_gcdext ##\n");
    init_one(&prev_t, MAX_BIGNUM_WORDS);  // prev_t = 1
    
    // Initialize g and b for the gcd calculation
    bn_copy(g, a);
    //bn_copy(b, b);

    while (!bn_is_zero(&b_temp)) {
        bn_divide(&quotient, &temp, g, &b_temp);
        
        // g = b
        bn_copy(g, &b_temp);
        // b = temp (remainder)
        bn_copy(&b_temp, &temp);

        // temp = (s - quotient * prev_s)
        bn_mul(&temp, &quotient, &prev_s); // temp = quotient * prev_s
        bn_subtract(&temp, s, &temp);      // temp = s - temp
        bn_copy(s, &prev_s);
        bn_copy(&prev_s, &temp);

        // temp = (t - quotient * prev_t)
        bn_mul(&temp, &quotient, &prev_t); // temp = quotient * prev_t
        bn_subtract(&temp, t, &temp);      // temp = t - temp
        bn_copy(t, &prev_t);
        bn_copy(&prev_t, &temp);
    }

    // Now g contains gcd(a, b), and s and t contain the Bezout coefficients
    printf(" -- bn_gcdext --\n");
}

/*__device__ void bn_mod_inverse_fixed_v0(BIGNUM *inverse, BIGNUM *x, BIGNUM *n) {
    // This assumes bn_gcdext has been implemented which calculates the gcd and the coefficient as gcdext does
    printf("++ bmi ++\n");
    BIGNUM gcd, coefficient, gcd_t;
    
    // Initialize gcd and coefficient
    init_zero(&gcd, MAX_BIGNUM_WORDS);
    init_zero(&coefficient, MAX_BIGNUM_WORDS);
    init_zero(&gcd_t, MAX_BIGNUM_WORDS);
    // Calculate gcd and coefficient where x * coefficient = gcd (mod n)
    bn_gcdext(&gcd, &coefficient, &gcd_t, x, n);
    // Check that the GCD is 1, ensuring an inverse exists
    if (!bn_is_one(&gcd)) {
        printf(" -- bmi: !bn_is_one(&gcd) --\n");
        return;
    }

    // Ensure the coefficient (inverse) is positive
    if (bn_is_negative(&coefficient)) {
        bn_add(inverse, &coefficient, n);
    } else {
        bn_copy(inverse, &coefficient);
    }

    // The inverse has been successfully calculated
    printf(" -- bmi --\n");
}*/

__device__ void bn_mod_inverse_fixed(BIGNUM *inverse, BIGNUM *a, BIGNUM *n) {
    printf("++ bn_mod_inverse_fixed ++\n");

    // Make sure bn_gcdext is implemented which calculates the gcd and the coefficient
    BIGNUM gcd, s, t, n_temp;

    // Initialize BIGNUM variables for intermediate calculations
    init_zero(&gcd, MAX_BIGNUM_WORDS);
    init_zero(&s, MAX_BIGNUM_WORDS);
    init_zero(&t, MAX_BIGNUM_WORDS);
    init_zero(&n_temp, MAX_BIGNUM_WORDS);

    // If n is 1 or zero, then inverse does not exist
    if (bn_is_one(n) || bn_is_zero(n)) {
        printf("No inverse exists for the given 'a' and 'n'.\n");
        return;
    }
    
    // Perform the extended GCD calculation (a, n, g, s, t)
    // On completion, s holds the modular inverse of a modulo n, if gcd(a, n) = 1
    bn_gcdext(&gcd, &s, &t, a, n);

    // Check if the GCD is one to make sure the inverse exists
    if (!bn_is_one(&gcd)) {
        printf("No inverse exists for the given 'a' and 'n'.\n");
        return;
    }

    // Print s and n
    bn_print("s: ", &s);
    bn_print("n: ", n);
    // The modular inverse can be negative, so if it's negative, add 'n' to make it positive
    if (bn_is_negative(&s)) {
        printf("bn_is_negative(&s)");
        bn_add(&n_temp, &s, n);   // n_temp = s + n
        bn_copy(inverse, &n_temp); // inverse = n_temp
    } else {
        printf("NOT bn_is_negative(&s)");
        bn_copy(inverse, &s); // inverse = s
    }

    printf(" -- bn_mod_inverse_fixed --\n");
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
        printf("== pd ==\n"); /*
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
