#include <limits.h>
#include <assert.h>
#include <stdio.h>
#include <stdint.h>

// #define BN_128

#ifdef BN_128
    #define BN_ULONG unsigned __int128
    #define BN_ULONG_MAX ((BN_ULONG)-1)
    #define MAX_BIGNUM_SIZE 5     // Reduced from 10 to 5 due to __int128
#else
    #define BN_ULONG unsigned long long
    #define BN_ULONG_MAX ((BN_ULONG)-1)
    #define MAX_BIGNUM_SIZE 10
#endif

#define debug_print true
#define BN_ULONG_NUM_BITS (sizeof(BN_ULONG) * 8)
#define PUBLIC_KEY_SIZE 33  // Assuming a 33-byte public key (compressed format)
#define DEVICE_CLOCK_RATE 1708500

typedef struct bignum_st {
    BN_ULONG d[MAX_BIGNUM_SIZE];
    unsigned char top;
    bool neg;
} BIGNUM;

// Initialize BIGNUM to zero
#ifdef BN_128
    __device__ const BIGNUM ZERO_BIGNUM = {
        {0,0,0,0,0},                  // d (will be properly initialized in init_zero)
        1,                    // top (unsigned char)
        0                    // neg (bool)
    };
#else
    __device__ const BIGNUM ZERO_BIGNUM = {
        {0,0,0,0,0,0,0,0,0,0},                  // d (will be properly initialized in init_zero)
        1,                    // top (unsigned char)
        0                    // neg (bool)
    };
#endif

__device__ void init_zero(BIGNUM *bn) {
    *bn = ZERO_BIGNUM;
}
__device__ void init_one(BIGNUM *bn) {
    // Initialize the BIGNUM to zero
    *bn = ZERO_BIGNUM;
    
    // Set the least significant word to 1
    bn->d[0] = 1;
    
    // Set the top to 1 (as there is one significant digit)
    bn->top = 1;
}

__device__ bool bn_add(BIGNUM *result, BIGNUM *a, BIGNUM *b);
__device__ int bn_mod(BIGNUM *r, BIGNUM *m, BIGNUM *d);
__device__ bool bn_is_zero(BIGNUM *a);

__device__ unsigned char find_top(const BIGNUM *bn) {
    for (int i = MAX_BIGNUM_SIZE - 1; i >= 0; i--) {
        if (bn->d[i] != 0) {
            return i + 1;
        }
    }
    return 1;
}

__device__ unsigned char find_top_optimized(const BIGNUM *bn, const char start_index) {
    const char start = start_index > MAX_BIGNUM_SIZE ? MAX_BIGNUM_SIZE : start_index;
    for (char i = start - 1; i >= 0; i--) {
        if (bn->d[i] != 0) {
            return i + 1;
        }
    }
    return 1;
}

__device__ void free_bignum(BIGNUM *bn) {
    delete[] bn->d;
}

__device__ void bn_print(const char* msg, BIGNUM* a) {
    if (!debug_print) return;
    
    printf("%s", msg);
    if (a->neg) {
        printf("-");  // Handle the case where BIGNUM is negative
    }
    for (int i = MAX_BIGNUM_SIZE - 1; i >= 0; i--) {
        // Print words up to top - 1 with appropriate formatting
        if (i == MAX_BIGNUM_SIZE - 1) {
            #ifdef BN_128
                printf("%016llx%016llx", (unsigned long long)(a->d[i] >> 64), (unsigned long long)(a->d[i] & 0xFFFFFFFFFFFFFFFFULL));
            #else
                printf("%llx", a->d[i]);
            #endif
        } else {
            #ifdef BN_128
                printf("%016llx%016llx", (unsigned long long)(a->d[i] >> 64), (unsigned long long)(a->d[i] & 0xFFFFFFFFFFFFFFFFULL));
            #else
                printf("%016llx", a->d[i]);
            #endif
        }
    }
    printf("\n");
}

__device__ void print_as_hex(const uint8_t *data, const uint32_t len) {
    for (uint32_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

__device__ void debug_printf(const char *fmt, ...) {
    if (debug_print) {
        printf(fmt);
    }
}

__device__ int bn_cmp(BIGNUM* a, BIGNUM* b) {
    // -1: a < b
    // 0: a == b
    // 1: a > b
    if (a->neg != b->neg) {
        return a->neg ? -1 : 1;
    }
    // a->top = find_top(a);
    b->top = find_top(b);
    if (a->top != b->top) {
        return a->top > b->top ? 1 : -1;
    }

    for (int i = a->top - 1; i >= 0; i--) {
        if (a->d[i] != b->d[i]) {
            return a->d[i] > b->d[i] ? 1 : -1;
        }
    }

    return 0;
}

__device__ int bn_cmp_abs(BIGNUM *a, BIGNUM *b) {
    if (a->top > b->top)
        return 1;
    if (b->top > a->top)
        return -1;

    for (int i = a->top - 1; i >= 0; i--) {
        if (a->d[i] > b->d[i])
            return 1;
        if (b->d[i] > a->d[i])
            return -1;
    }
    return 0;
}

// Helper function to perform a deep copy of BIGNUM
__device__ void bn_copy(BIGNUM *dest, BIGNUM *src) {
    // Init dst as zero
    init_zero(dest);

    if (dest == nullptr || src == nullptr) {
        return;
    }

    // Copy the neg and top fields
    dest->neg = src->neg;
    dest->top = src->top;

    int i;

    // Copy the array of BN_ULONG digits.
    for (i = 0; i < src->top; i++) {
        dest->d[i] = src->d[i];
    }

    // Set the rest of the words in dest to 0 if dest's top is larger
    for (i = src->top; i < MAX_BIGNUM_SIZE; i++) {
        dest->d[i] = 0;
    }
}

__device__ void absolute_add(BIGNUM *result, const BIGNUM *a, const BIGNUM *b) {
    // Determine the maximum size to iterate over
    unsigned char max_top = max(a->top, b->top);
    BN_ULONG carry = 0;

    unsigned char i;

    // Initialize result
    for (i = 0; i <= max_top; ++i) {
        result->d[i] = 0;
    }
    result->top = max_top;

    for (i = 0; i <= max_top; ++i) {
        // Extract current words or zero if one bignum is shorter
        BN_ULONG ai = (i < a->top) ? a->d[i] : 0;
        BN_ULONG bi = (i < b->top) ? b->d[i] : 0;

        #ifdef BN_128
            // Split the 128-bit numbers into high and low 64-bit parts
            uint64_t ai_lo = (uint64_t)ai;
            uint64_t ai_hi = (uint64_t)(ai >> 64);
            uint64_t bi_lo = (uint64_t)bi;
            uint64_t bi_hi = (uint64_t)(bi >> 64);

            // Perform addition on low parts
            uint64_t sum_lo = ai_lo + bi_lo + (uint64_t)carry;
            uint64_t carry_lo = (sum_lo < ai_lo) || (carry && sum_lo == ai_lo);

            // Perform addition on high parts
            uint64_t sum_hi = ai_hi + bi_hi + carry_lo;
            uint64_t carry_hi = (sum_hi < ai_hi) || (carry_lo && sum_hi == ai_hi);

            // Combine high and low parts back into 128-bit word
            BN_ULONG sum = ((BN_ULONG)sum_hi << 64) | sum_lo;
            result->d[i] = sum;

            // Update carry
            carry = carry_hi;
        #else
            // Calculate sum and carry
            BN_ULONG sum = ai + bi + carry;

            // Store result
            result->d[i] = sum; // No need for masking as BN_ULONG is already the correct size

            // Calculate carry
            carry = (sum < ai) || (carry > 0 && sum == ai) ? 1 : 0;
        #endif
    }

    // Handle carry out, expand result if necessary
    if (carry > 0) {
        if (result->top < MAX_BIGNUM_SIZE - 1) {
            result->d[result->top] = carry;
            result->top++;
        } else {
            // Handle error: Result BIGNUM doesn't have space for an additional word.
            // This should potentially be reported back to the caller.
            printf("absolute_add: Result BIGNUM doesn't have space for an additional word.\n");
        }
    }

    // Find the real top after addition (no leading zeroes)
    result->top = find_top_optimized(result, max_top+1);
}

__device__ void absolute_subtract(BIGNUM *result, BIGNUM *a, BIGNUM *b) {

    unsigned char max_top = max(a->top, b->top);
    BN_ULONG borrow = 0;
    result->top = max_top;

    for (unsigned char i = 0; i < max_top; ++i) {
        BN_ULONG ai = (i < a->top) ? a->d[i] : 0;
        BN_ULONG bi = (i < b->top) ? b->d[i] : 0;

        // Perform subtraction
        BN_ULONG diff = ai - bi - borrow;
        
        // Check if borrow occurred
        if (ai < bi || (borrow && ai == bi)) {
            borrow = 1;
        } else {
            borrow = 0;
        }

        result->d[i] = diff;
    }

    // Normalize the result (remove leading zeros)
    while (result->top > 0 && result->d[result->top - 1] == 0) {
        result->top--;
    }

    // If the result is zero, ensure top is set to 1 and d[0] is 0
    if (result->top == 0) {
        result->top = 1;
        result->d[0] = 0;
    }
}

__device__ bool bn_sub(BIGNUM *result, BIGNUM *a, BIGNUM *b) {
    // If one is negative and the other is positive, it's essentially an addition.
    if (a->neg != b->neg) {
        result->neg = a->neg; // The sign will be the same as the sign of 'a'.
        absolute_add(result, a, b); // Perform the addition of magnitudes here because signs are different.
        return true;
    }

    // Compare the absolute values to decide the order of subtraction and sign of the result.
    int cmp_res = bn_cmp_abs(a, b); // This function should compare the absolute values of 'a' and 'b'.
    
    if (cmp_res >= 0) {
        // |a| >= |b|, perform a - b, result takes sign from 'a'.
        result->neg = a->neg;
        absolute_subtract(result, a, b);
    } else {
        // |b| > |a|, perform b - a instead, result takes opposite sign from 'a'.
        result->neg = !a->neg;
        absolute_subtract(result, b, a);
    }

    // Perform additional logic if underflow has been detected in absolute_subtract.
    if (result->top == 0) { 
        // Handle underflow if needed. 
    }
    return true;
}

__device__ int absolute_compare(const BIGNUM* a, const BIGNUM* b) {
    // absolute_compare logic:
    //  1 when |a| is larger
    // -1 when |b| is larger
    //  0 when |a| and |b| are equal in absolute value

    // Skip leading zeros and find the actual top for a
    int a_top = a->top - 1;
    while (a_top >= 0 && a->d[a_top] == 0) a_top--;

    // Skip leading zeros and find the actual top for b
    int b_top = b->top - 1;
    while (b_top >= 0 && b->d[b_top] == 0) b_top--;

    // Compare actual tops
    if (a_top > b_top) return 1; // |a| is larger
    if (a_top < b_top) return -1; // |b| is larger

    // Both numbers have the same number of significant digits, compare digit by digit
    for (int i = a_top; i >= 0; i--) {
        if (a->d[i] > b->d[i]) return 1; // |a| is larger
        if (a->d[i] < b->d[i]) return -1; // |b| is larger
    }
    return 0; // |a| and |b| are equal in absolute value
}

__device__ bool bn_add(BIGNUM *result, BIGNUM *a, BIGNUM *b) {
    init_zero(result);
    unsigned char max_top = max(a->top, b->top);

    if (a->neg == b->neg) {
        // Both numbers have the same sign, so we can directly add them.
        absolute_add(result, a, b);
        result->neg = a->neg; // The sign will be the same as both operands.
    } else {
        // The numbers have different signs, so we need to compare their absolute values to decide on the operation.
        int cmp_result = absolute_compare(a, b);
        if (cmp_result < 0) {
            // |b| is greater than |a|, so we'll do b - a and assign the sign of b to the result.
            absolute_subtract(result, b, a);
            result->neg = b->neg;
        } else if (cmp_result > 0) {
            // |a| is greater than |b|, so we'll do a - b and assign the sign of a to the result.
            absolute_subtract(result, a, b);
            result->neg = a->neg;
        } else {
            // |a| is equal to |b|, so the result is 0.
            // The result of adding two numbers with different signs but equal magnitude is 0.
            result->neg = 0; // Set sign to 0 for non-negative.
            result->top = 1; // The result is 0, so top is 1 to denote one valid word which is zero.
            result->d[0] = 0;
        }
    }
    return true;
}

__device__ int bn_div(BIGNUM *a, BIGNUM *b, BIGNUM *q, BIGNUM *r);
__device__ void bn_mul(BIGNUM *a, BIGNUM *b, BIGNUM *product);

__device__ void set_bn(BIGNUM *dest, const BIGNUM *src) {
    debug_printf("set_bn 0\n");

    // Check if dest has enough space to copy from src
    if (MAX_BIGNUM_SIZE < src->top) {    
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
    for (int i = src->top; i < MAX_BIGNUM_SIZE; ++i) {
        debug_printf("set_bn 2.%d\n", i);
        dest->d[i] = 0;
    }

    debug_printf("set_bn 3\n");

    // Set the 'top' and 'neg' flags after zeroing
    dest->top = src->top;
    dest->neg = src->neg;
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
    init_zero(&zero);
    BIGNUM temp_remainder;
    init_zero(&temp_remainder);

    while (bn_cmp(&remainder, &zero) != 0) {
        bn_div(&last_remainder, &remainder, &quotient, &temp_remainder);
        BIGNUM swap_temp = last_remainder; // Temporary storage for the swap
        bn_copy(&last_remainder, &temp_remainder);
        bn_copy(&temp_remainder, &swap_temp);

        bn_mul(&quotient, x, &temp); // temp = quotient*x
        bn_sub(&prev_x, &temp, &prev_x); // new prev_x = prev_x - temp
        bn_mul(&quotient, y, &temp); // temp = quotient*y
        bn_sub(&last_y, &temp, &last_y); // new last_y = last_y - temp
    }

    // Clean up
    delete &temp_remainder; // Only if dynamic memory is allowed - if you statically allocated, this is unnecessary
    
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

__device__ void bn_mul_64_version_0(BIGNUM *a, BIGNUM *b, BIGNUM *product) {
    init_zero(product);
    
    // Perform multiplication of each word of a with each word of b
    for (int i = 0; i < a->top; ++i) {
        unsigned long long carry = 0;
        for (int j = 0; j < b->top || carry != 0; ++j) {
            unsigned long long alow = a->d[i];
            unsigned long long blow = (j < b->top) ? b->d[j] : 0;
            unsigned long long lolo = alow * blow;
            unsigned long long lohi = __umul64hi(alow, blow);
            // Corrected handling: 
            unsigned long long sumLow = product->d[i + j] + lolo;
            unsigned long long carryLow = (sumLow < product->d[i + j]) ? 1 : 0; // overflowed?

            unsigned long long sumHigh = sumLow + carry;
            unsigned long long carryHigh = (sumHigh < sumLow) ? 1 : 0; // overflowed?

            product->d[i + j] = sumHigh;

            // Aggregate carry: contributions from high multiplication and overflows
            carry = lohi + carryLow + carryHigh;
        }
        // Store final carry if it exists
        if (carry != 0) {
            product->d[i + b->top] = carry;
        }
    }

    // Update the top to reflect the number of significant words in the product
    product->top = 0;
    for(int i = a->top + b->top - 1; i >= 0; --i) {
        if(product->d[i] != 0) {
            product->top = i + 1;
            break;
        }
    }

    // If the result has no significant words, ensure that top is at least 1
    if(product->top == 0)
        product->top = 1;
    
    // Determine if the result should be negative
    product->neg = (a->neg != b->neg) ? 1 : 0;
}

__device__ void bn_mul_64_version_1(BIGNUM *a, BIGNUM *b, BIGNUM *product) {
    init_zero(product);
    
    for (int i = 0; i < a->top; ++i) {
        unsigned int a_lo = (unsigned int)(a->d[i]);
        unsigned int a_hi = (unsigned int)(a->d[i] >> 32);
        unsigned long long carry = 0;
        for (int j = 0; j < b->top || carry != 0; ++j) {
            unsigned int b_lo = (unsigned int)((j < b->top) ? b->d[j] : 0);
            unsigned int b_hi = (unsigned int)(((j < b->top) ? b->d[j] : 0) >> 32);

            // Perform multiplication using 32-bit halves
            unsigned long long lo_lo = (unsigned long long)a_lo * b_lo;
            unsigned long long lo_hi = (unsigned long long)a_lo * b_hi;
            unsigned long long hi_lo = (unsigned long long)a_hi * b_lo;
            unsigned long long hi_hi = (unsigned long long)a_hi * b_hi;

            // Combine the results
            unsigned long long temp = product->d[i + j] + (lo_lo & 0xFFFFFFFF) + (carry & 0xFFFFFFFF);
            unsigned long long new_carry = (temp >> 32) + (lo_lo >> 32) + (lo_hi & 0xFFFFFFFF) + (hi_lo & 0xFFFFFFFF) + (carry >> 32);
            product->d[i + j] = (temp & 0xFFFFFFFF) | (new_carry << 32);
            carry = (new_carry >> 32) + (lo_hi >> 32) + (hi_lo >> 32) + hi_hi;
        }
        if (carry != 0) {
            product->d[i + b->top] = carry;
        }
    }
    
    // Update the top
    product->top = a->top + b->top;
    while (product->top > 1 && product->d[product->top - 1] == 0) {
        --product->top;
    }
    product->neg = a->neg ^ b->neg;
}

// Helper function to split a BIGNUM into two halves
__device__ void bn_split(BIGNUM *a, int m, BIGNUM *a1, BIGNUM *a0) {
    init_zero(a0);
    init_zero(a1);

    // Copy lower m words to a0
    for (int i = 0; i < m && i < a->top; i++) {
        a0->d[i] = a->d[i];
    }
    a0->top = min(m, a->top);

    // Copy higher words to a1
    for (int i = m; i < a->top; i++) {
        a1->d[i - m] = a->d[i];
    }
    a1->top = (a->top > m) ? (a->top - m) : 0;
}

// Helper function to left-shift a BIGNUM by 'words' words
__device__ void bn_lshift_words(BIGNUM *result, BIGNUM *a, int words) {
    init_zero(result);

    // Shift a left by 'words' words
    for (int i = 0; i < a->top && (i + words) < MAX_BIGNUM_SIZE; i++) {
        result->d[i + words] = a->d[i];
    }
    result->top = a->top + words;

    // Ensure we don't exceed MAX_BIGNUM_SIZE
    if (result->top > MAX_BIGNUM_SIZE) {
        result->top = MAX_BIGNUM_SIZE;
    }
}

// Base case multiplication for small sizes
__device__ void bn_mul_basecase(BIGNUM *a, BIGNUM *b, BIGNUM *product) {
    init_zero(product);

    for (int i = 0; i < a->top; i++) {
        BN_ULONG carry = 0;
        for (int j = 0; j < b->top || carry != 0; j++) {
            BN_ULONG ai = a->d[i];
            BN_ULONG bj = (j < b->top) ? b->d[j] : 0;

            // Use 128-bit arithmetic if available
            unsigned __int128 temp = (unsigned __int128)ai * bj + product->d[i + j] + carry;
            product->d[i + j] = (BN_ULONG)temp;
            carry = (BN_ULONG)(temp >> 64);
        }
    }

    // Update the top
    product->top = a->top + b->top;
    while (product->top > 1 && product->d[product->top - 1] == 0) {
        product->top--;
    }

    product->neg = a->neg ^ b->neg;
}

// Karatsuba multiplication
// Need to increase "error = cudaDeviceSetLimit(cudaLimitStackSize, 1024 * 64);" in main.cu to prevent overflow    
__device__ void bn_mul_Karatsuba_64(BIGNUM *a, BIGNUM *b, BIGNUM *product) {
    init_zero(product);

    // Determine the size
    int n = max(a->top, b->top);

    // Base case threshold
    const int KARATSUBA_THRESHOLD = 2;

    // Base case: Use standard multiplication for small n
    if (n <= KARATSUBA_THRESHOLD) {
        bn_mul_basecase(a, b, product);
        return;
    }

    // Limit n to prevent exceeding MAX_BIGNUM_SIZE
    if (n > MAX_BIGNUM_SIZE / 2) {
        bn_mul_basecase(a, b, product);
        return;
    }

    int m = n / 2;

    // Split a into a1 and a0
    BIGNUM a0, a1;
    bn_split(a, m, &a1, &a0);

    // Split b into b1 and b0
    BIGNUM b0, b1;
    bn_split(b, m, &b1, &b0);

    // Compute z0 = a0 * b0
    BIGNUM z0;
    bn_mul(&a0, &b0, &z0);

    // Compute z2 = a1 * b1
    BIGNUM z2;
    bn_mul(&a1, &b1, &z2);

    // Compute (a0 + a1)
    BIGNUM a0_plus_a1;
    bn_add(&a0_plus_a1, &a0, &a1);

    // Compute (b0 + b1)
    BIGNUM b0_plus_b1;
    bn_add(&b0_plus_b1, &b0, &b1);

    // Compute z1 = (a0 + a1) * (b0 + b1) - z0 - z2
    BIGNUM z1, temp;
    bn_mul(&a0_plus_a1, &b0_plus_b1, &z1);
    bn_sub(&temp, &z1, &z0);
    bn_sub(&z1, &temp, &z2);

    // Shift z2 by 2*m words
    BIGNUM z2_shifted;
    bn_lshift_words(&z2_shifted, &z2, 2 * m);

    // Shift z1 by m words
    BIGNUM z1_shifted;
    bn_lshift_words(&z1_shifted, &z1, m);

    // Combine the results: product = z2_shifted + z1_shifted + z0
    BIGNUM temp_sum;
    bn_add(&temp_sum, &z2_shifted, &z1_shifted);
    bn_add(product, &temp_sum, &z0);

    // Determine the sign of the product
    product->neg = a->neg ^ b->neg;

    // Ensure that the top is updated correctly
    product->top = find_top(product);
}

__device__ void bn_mul(BIGNUM *a, BIGNUM *b, BIGNUM *product) {
    init_zero(product);

    #ifdef BN_128
        for (int i = 0; i < a->top; ++i) {
            uint64_t a_lo = (uint64_t)a->d[i];
            uint64_t a_hi = (uint64_t)(a->d[i] >> 64);
            BN_ULONG carry = 0;

            for (int j = 0; j < b->top; ++j) {
                uint64_t b_lo = (uint64_t)b->d[j];
                uint64_t b_hi = (uint64_t)(b->d[j] >> 64);

                // Multiply parts
                unsigned __int128 lo_lo = (unsigned __int128)a_lo * b_lo;
                unsigned __int128 lo_hi = (unsigned __int128)a_lo * b_hi;
                unsigned __int128 hi_lo = (unsigned __int128)a_hi * b_lo;
                unsigned __int128 hi_hi = (unsigned __int128)a_hi * b_hi;

                // Cross terms
                unsigned __int128 cross = lo_hi + hi_lo;
                unsigned int cross_carry = (cross < lo_hi) ? 1 : 0;

                // Combine lower 128 bits
                unsigned __int128 temp_low = lo_lo + (cross << 64);
                unsigned int low_carry = (temp_low < lo_lo) ? 1 : 0;

                // Combine higher bits
                unsigned __int128 temp_high = hi_hi + (cross >> 64) + cross_carry + low_carry;

                // Add to product
                unsigned __int128 sum = product->d[i + j] + temp_low + carry;
                unsigned int sum_carry = (sum < product->d[i + j]) ? 1 : 0;
                sum_carry += (sum < temp_low) ? 1 : 0;

                product->d[i + j] = sum;
                carry = temp_high + sum_carry;
            }
            product->d[i + b->top] = carry;
        }
    #else
        // Unroll loops if possible
        for (int i = 0; i < a->top; i++) {
            BN_ULONG carry = 0;
            for (int j = 0; j < b->top; j++) {
                unsigned __int128 temp = (unsigned __int128)a->d[i] * b->d[j] + product->d[i + j] + carry;
                product->d[i + j] = (BN_ULONG)temp;
                carry = (BN_ULONG)(temp >> 64);
            }
            product->d[i + b->top] = carry;
        }
    #endif

    // Update the top
    product->top = a->top + b->top;
    while (product->top > 1 && product->d[product->top - 1] == 0) {
        product->top--;
    }

    product->neg = a->neg ^ b->neg;
}

__device__ int bn_mod(BIGNUM *r, BIGNUM *a, BIGNUM *n) {
    // r: Remainder (updated)
    // a: Dividend
    // n: Modulus
    bool debug = 0;
    BIGNUM q;
    init_zero(&q);

    if (r == n) {
        printf("bn_mod: ERR_R_PASSED_INVALID_ARGUMENT");
        return 0;
    }
    if (!bn_div(&q, r, a, n)) {
        return 0;
    }

    BIGNUM tmp;
    init_zero(&tmp);

    if (r->neg) {
        if (debug) printf("r is negative\n");
        bool result;
        // If the remainder is negative, add the absolute value of the divisor
        if (n->neg) {
            if (debug) printf("d is negative\n");
            result = bn_sub(&tmp, r, n); // tmp = r - n
            if (!result) {
                return 0;
            }
            // copy tmp to r
            bn_copy(r, &tmp);
        } else {
            if (debug) printf("d is not negative\n");
            result = bn_add(&tmp, r, n); // tmp = r + n            
            if (!result) {
                return 0;
            }
            // copy tmp to r
            bn_copy(r, &tmp);
        }
    }
    if (debug) bn_print("<< r bn_mod: ", r);
    if (debug) printf("-- bn_mod --\n");
    return 1;
}

__device__ void mod_mul(BIGNUM *a, BIGNUM *b, BIGNUM *mod, BIGNUM *result) {
    debug_printf("mod_mul 0\n");
    BIGNUM product;
    init_zero(&product);
    debug_printf("mod_mul 1\n");
    // Now, you can call the bn_mul function and pass 'product' to it
    bn_mul(a, b, &product);
    debug_printf("mod_mul 2\n");
    
    
    bn_mod(&product, mod, result);

    debug_printf("mod_mul 3\n");
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
    for (int i = 1; i < MAX_BIGNUM_SIZE; ++i) {
        if (a->d[i] != 0) {
            return false;
        }
    }
    return true;
}

__device__ void bn_set_word(BIGNUM *bn, BN_ULONG word) {
    // Assuming d is a pointer to an array where the BIGNUM's value is stored
    // and top is an integer representing the index of the most significant word + 1
    // Setting a BIGNUM to a single-word value means that all other words are zero.

    // Clear all words in the BIGNUM
    for (int i = 0; i < MAX_BIGNUM_SIZE; ++i) {
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

__device__ void left_shift(BIGNUM *a, int shift) {
    if (shift == 0) return;  // No shift needed

    int word_shift = shift / BN_ULONG_NUM_BITS;
    int bit_shift = shift % BN_ULONG_NUM_BITS;

    // Shift whole words
    if (word_shift > 0) {
        for (int i = MAX_BIGNUM_SIZE - 1; i >= word_shift; i--) {
            a->d[i] = a->d[i - word_shift];
        }
        for (int i = 0; i < word_shift; i++) {
            a->d[i] = 0;
        }
    }

    // Shift remaining bits
    if (bit_shift > 0) {
        BN_ULONG carry = 0;
        for (int i = 0; i < MAX_BIGNUM_SIZE; i++) {
            BN_ULONG new_carry = a->d[i] >> (BN_ULONG_NUM_BITS - bit_shift);
            a->d[i] = (a->d[i] << bit_shift) | carry;
            carry = new_carry;
        }
    }

    // Calculate new top
    unsigned char potential_new_top = a->top + (shift + BN_ULONG_NUM_BITS - 1) / BN_ULONG_NUM_BITS;
    a->top = find_top_optimized(a, potential_new_top);
}

__device__ int bn_div_x(BIGNUM *bn_quotient, BIGNUM *bn_remainder, BIGNUM *bn_dividend, BIGNUM *bn_divisor)
{
    // Store signs and work with absolute values
    int dividend_neg = bn_dividend->neg;
    int divisor_neg = bn_divisor->neg;
    BIGNUM abs_dividend, abs_divisor;
    init_zero(&abs_dividend);
    init_zero(&abs_divisor);

    unsigned char divs_max_top = (bn_dividend->top > bn_divisor->top) ? bn_dividend->top : bn_divisor->top;

    // Copy absolute values
    for (int i = 0; i < divs_max_top; i++) {
        abs_dividend.d[i] = bn_dividend->d[i];
        abs_divisor.d[i] = bn_divisor->d[i];
    }
    abs_dividend.neg = 0;
    abs_divisor.neg = 0;
    abs_dividend.top = bn_dividend->top;
    abs_divisor.top = bn_divisor->top;

    // Initialize quotient and remainder
    init_zero(bn_quotient);
    init_zero(bn_remainder);

    // Handle special cases
    if (bn_cmp(&abs_dividend, &abs_divisor) == 0) {
        bn_quotient->d[0] = 1;
        bn_quotient->top = 1;
        bn_quotient->neg = (dividend_neg != divisor_neg);
        printf("abs_dividend == abs_divisor. Quotient = 1\n");
        return 1;
    }
    // Perform long division
    BIGNUM current_dividend;
    init_zero(&current_dividend);
    char dividend_size = abs_dividend.top;

    for (int i = dividend_size - 1; i >= 0; i--) {
        // Shift current_dividend left by one word and add next word of dividend
        left_shift(&current_dividend, 64);
        current_dividend.d[0] = abs_dividend.d[i];

        // Find quotient digit
        BN_ULONG q = 0;
        BN_ULONG left = 0, right = UINT64_MAX;
        while (left <= right) {
            BN_ULONG mid = left + (right - left) / 2;
            BIGNUM temp, product;
            init_zero(&temp);
            init_zero(&product);
            temp.d[0] = mid;
            temp.top = 1;

            bn_mul(&abs_divisor, &temp, &product);

            if (bn_cmp(&product, &current_dividend) <= 0) {
                q = mid;
                left = mid + 1;
            } else {
                right = mid - 1;
            }
        }

        // Add quotient digit to result
        left_shift(bn_quotient, 64);
        bn_quotient->d[0] |= q;

        // Subtract q * divisor from current_dividend
        BIGNUM temp, product;
        init_zero(&temp);
        init_zero(&product);
        temp.d[0] = q;
        temp.top = 1;

        bn_mul(&abs_divisor, &temp, &product);

        bn_sub(&current_dividend, &current_dividend, &product);
    }

    // Set remainder
    // for (int i = 0; i < MAX_BIGNUM_SIZE; i++) {
    for (int i = 0; i < current_dividend.top; i++) {
        bn_remainder->d[i] = current_dividend.d[i];
    }

    // Apply correct signs
    bn_quotient->neg = (dividend_neg != divisor_neg);
    bn_remainder->neg = dividend_neg;

    // Normalize results
    bn_quotient->top = find_top_optimized(bn_quotient, divs_max_top);
    bn_remainder->top = find_top_optimized(bn_remainder, divs_max_top);
    return 1;
}

__device__ int bn_div(BIGNUM *bn_quotient, BIGNUM *bn_remainder, BIGNUM *bn_dividend, BIGNUM *bn_divisor)
{
    // Store signs and work with absolute values
    int dividend_neg = bn_dividend->neg;
    int divisor_neg = bn_divisor->neg;
    BIGNUM abs_dividend, abs_divisor;
    init_zero(&abs_dividend);
    init_zero(&abs_divisor);

    unsigned char divs_max_top = (bn_dividend->top > bn_divisor->top) ? bn_dividend->top : bn_divisor->top;

    // Copy absolute values
    for (int i = 0; i < divs_max_top; i++) {
        abs_dividend.d[i] = bn_dividend->d[i];
        abs_divisor.d[i] = bn_divisor->d[i];
    }
    abs_dividend.neg = 0;
    abs_divisor.neg = 0;
    abs_dividend.top = bn_dividend->top;
    abs_divisor.top = bn_divisor->top;

    // Initialize quotient and remainder
    init_zero(bn_quotient);
    init_zero(bn_remainder);

    // Handle special cases
    if (bn_cmp(&abs_dividend, &abs_divisor) == 0) {
        bn_quotient->d[0] = 1;
        bn_quotient->top = 1;
        bn_quotient->neg = (dividend_neg != divisor_neg);
        printf("abs_dividend == abs_divisor. Quotient = 1\n");
        return 1;
    }
    // Perform long division
    BIGNUM current_dividend;
    init_zero(&current_dividend);
    char dividend_size = abs_dividend.top;

    for (int i = dividend_size - 1; i >= 0; i--) {
        // Shift current_dividend left by one word and add next word of dividend
        left_shift(&current_dividend, BN_ULONG_NUM_BITS);
        current_dividend.d[0] = abs_dividend.d[i];

        // Find quotient digit
        BN_ULONG q = 0;
        BN_ULONG left = 0, right = BN_ULONG_MAX;
        while (left <= right) {
            BN_ULONG mid = left + (right - left) / 2;
            BIGNUM temp, product;
            init_zero(&temp);
            init_zero(&product);
            temp.d[0] = mid;
            temp.top = 1;

            bn_mul(&abs_divisor, &temp, &product);

            if (bn_cmp(&product, &current_dividend) <= 0) {
                q = mid;
                left = mid + 1;
            } else {
                right = mid - 1;
            }
        }

        // Add quotient digit to result
        left_shift(bn_quotient, 64);
        bn_quotient->d[0] |= q;

        // Subtract q * divisor from current_dividend
        BIGNUM temp, product;
        init_zero(&temp);
        init_zero(&product);
        temp.d[0] = q;
        temp.top = 1;

        bn_mul(&abs_divisor, &temp, &product);

        bn_sub(&current_dividend, &current_dividend, &product);
    }

    // Set remainder
    // for (int i = 0; i < MAX_BIGNUM_SIZE; i++) {
    for (int i = 0; i < current_dividend.top; i++) {
        bn_remainder->d[i] = current_dividend.d[i];
    }

    // Apply correct signs
    bn_quotient->neg = (dividend_neg != divisor_neg);
    bn_remainder->neg = dividend_neg;

    // Normalize results
    bn_quotient->top = find_top_optimized(bn_quotient, divs_max_top);
    bn_remainder->top = find_top_optimized(bn_remainder, divs_max_top);
    return 1;
}

__device__ int bn_div_word(BIGNUM *bn_quotient, BN_ULONG *remainder, BIGNUM *bn_dividend, BN_ULONG bn_divisor) {
    init_zero(bn_quotient);
    BN_ULONG rem = 0;

    for (int i = bn_dividend->top - 1; i >= 0; i--) {
        __uint128_t dividend_part = ((__uint128_t)rem << BN_ULONG_NUM_BITS) | bn_dividend->d[i];
        BN_ULONG qword = dividend_part / bn_divisor;
        rem = dividend_part % bn_divisor;

        bn_quotient->d[i] = qword;
    }
    bn_quotient->top = bn_dividend->top;
    *remainder = rem;

    // Adjust top
    while (bn_quotient->top > 0 && bn_quotient->d[bn_quotient->top - 1] == 0) {
        bn_quotient->top--;
    }

    return 1;
}

__device__ int bn_div_y(BIGNUM *bn_quotient, BIGNUM *bn_remainder, BIGNUM *bn_dividend, BIGNUM *bn_divisor) {
    // Handle signs and take absolute values
    int dividend_neg = bn_dividend->neg;
    int divisor_neg = bn_divisor->neg;
    BIGNUM abs_dividend, abs_divisor;
    bn_copy(&abs_dividend, bn_dividend);
    bn_copy(&abs_divisor, bn_divisor);
    abs_dividend.neg = 0;
    abs_divisor.neg = 0;

    init_zero(bn_quotient);
    init_zero(bn_remainder);

    // If divisor is zero, return error
    if (bn_is_zero(&abs_divisor)) {
        printf("Division by zero error\n");
        return 0;
    }

    // If divisor is single-word, use bn_div_word
    if (abs_divisor.top == 1) {
        BN_ULONG rem;
        bn_div_word(bn_quotient, &rem, &abs_dividend, abs_divisor.d[0]);
        bn_remainder->d[0] = rem;
        bn_remainder->top = (rem == 0) ? 0 : 1;
    } else {
        // Implement multi-word division algorithm here
        // This requires more complex logic
    }

    // Set signs
    bn_quotient->neg = (dividend_neg != divisor_neg);
    bn_remainder->neg = dividend_neg;

    return 1;
}