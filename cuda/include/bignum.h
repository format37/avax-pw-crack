#include <limits.h>
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include "function_profiling.h"

#define BN_128
// #define debug_print
// #define debug_bn_copy
// #define debug_top
#define function_profiler

#ifdef BN_128
    #define BN_ULONG unsigned __int128
    #define uint128_t unsigned __int128
    #define BN_ULONG_MAX ((BN_ULONG)-1)
    #define MAX_BIGNUM_SIZE 5     // Reduced from 10 to 5 due to __int128
#else
    #define BN_ULONG unsigned long long
    #define BN_ULONG_MAX ((BN_ULONG)-1)
    #define MAX_BIGNUM_SIZE 10
#endif

#define MAX_BIT_ARRAY_SIZE 256 // Limit to 256 bits to match the function's design
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
        {0},                  // d (will be properly initialized in init_zero)
        1,                    // top (unsigned char)
        0                    // neg (bool)
    };
#else
    __device__ const BIGNUM ZERO_BIGNUM = {
        {0},                  // d (will be properly initialized in init_zero)
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

// __device__ bool bn_add(BIGNUM *result, BIGNUM *a, BIGNUM *b);
__device__ bool bn_add(BIGNUM *result, const BIGNUM *a, const BIGNUM *b);
// __device__ int bn_mod(BIGNUM *r, BIGNUM *m, BIGNUM *d);
__device__ int bn_mod(BIGNUM *r, const BIGNUM *a, const BIGNUM *n);
__device__ bool bn_is_zero(const BIGNUM *a);

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

__device__ void bn_print(const char* msg, const BIGNUM* a) {
    // if (!debug_print) return;
    #ifndef debug_print
        return;
    #endif
    
    #ifdef debug_top
        if (a->top != find_top(a)) printf("### ERROR: bn_print: a->top (%d) != find_top(a) (%d)\n", a->top, find_top(a));
    #endif
    printf("%s", msg);
    printf("[");
    if (a->neg) printf("-");
    else printf("+");
    printf("%d] ", a->top);
    if (a->neg) {
        printf("-");  // Handle the case where BIGNUM is negative
    }
    // for (int i = MAX_BIGNUM_SIZE - 1; i >= 0; i--) {
    for (int i = a->top - 1; i >= 0; i--) {
        // Print words up to top - 1 with appropriate formatting
        // if (i == MAX_BIGNUM_SIZE - 1) {
        if (i == a->top - 1) {
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
        // return;
    }
    printf("\n");
}

__device__ void bn_print_no_fuse(const char* msg, const BIGNUM* a) {   
    #ifdef debug_top
        if (a->top != find_top(a)) printf("### ERROR: bn_print: a->top (%d) != find_top(a) (%d)\n", a->top, find_top(a));
    #endif
    printf("%s", msg);
    printf("[");
    if (a->neg) printf("-");
    else printf("+");
    printf("%d] ", a->top);
    if (a->neg) {
        printf("-");  // Handle the case where BIGNUM is negative
    }
    // for (int i = MAX_BIGNUM_SIZE - 1; i >= 0; i--) {
    for (int i = a->top - 1; i >= 0; i--) {
        // Print words up to top - 1 with appropriate formatting
        // if (i == MAX_BIGNUM_SIZE - 1) {
        if (i == a->top - 1) {
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
        // return;
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
    // if (debug_print) {
    #ifdef debug_print
        printf(fmt);
    #endif
    // }
}

__device__ int bn_cmp(const BIGNUM* a, const BIGNUM* b) {
    // -1: a < b
    // 0: a == b
    // 1: a > b
    #ifdef debug_print
        // printf("++ bn_cmp ++\n");
        // bn_print(">> a: ", a);
        // bn_print(">> b: ", b);
    #endif
    if (a->neg != b->neg) {
        #ifdef debug_print
            // printf("a->neg != b->neg\n-- bn_cmp --\n");
        #endif
        return a->neg ? -1 : 1;
    }
    #ifdef debug_top
        if (a->top != find_top(a)) printf("### ERROR: bn_cmp: a->top != find_top(a)\n");
        if (b->top != find_top(b)) printf("### ERROR: bn_cmp: b->top != find_top(b)\n");
    #endif
    if (a->top != b->top) {
        #ifdef debug_print
            // printf("a->top != b->top\n-- bn_cmp --\n");
        #endif
        return a->top > b->top ? 1 : -1;
    }

    for (int i = a->top - 1; i >= 0; i--) {
        if (a->d[i] != b->d[i]) {
            #ifdef debug_print
                // printf("a->d[i] != b->d[i]\n-- bn_cmp --\n");
            #endif
            return a->d[i] > b->d[i] ? 1 : -1;
        }
    }
    #ifdef debug_print
        // printf("default case\n-- bn_cmp --\n");
    #endif
    return 0;
}

__device__ int bn_cmp_abs(const BIGNUM *a, const BIGNUM *b) {
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
__device__ void bn_copy(BIGNUM *dest, const BIGNUM *src) {
    #ifdef debug_print
        // printf("++ bn_copy ++\n");
        // bn_print(">> src: ", src);
        // bn_print(">> dest: ", dest);
    #endif
    // Init dst as zero
    init_zero(dest);

    if (dest == nullptr || src == nullptr) {
        return;
    }
    #ifdef debug_top
        if (src->top != find_top(src)) printf("### ERROR: bn_copy: src->top (%d) != find_top(src) (%d)\n", src->top, find_top(src));
        if (src->top > MAX_BIGNUM_SIZE) {
            printf("### bn_copy ERROR: src->top > MAX_BIGNUM_SIZE\n");
        }
    #endif

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
    #ifdef debug_print
        // bn_print("<< dest: ", dest);
        // printf("-- bn_copy --\n");
    #endif
}

#ifdef BN_128
    __device__ void absolute_add(BIGNUM *result, const BIGNUM *a, const BIGNUM *b) {
        unsigned char max_top = max(a->top, b->top);
        volatile BN_ULONG carry = 0;

        for (int i = 0; i <= max_top; ++i) {
            volatile BN_ULONG ai = (i < a->top) ? a->d[i] : 0;
            volatile BN_ULONG bi = (i < b->top) ? b->d[i] : 0;
            volatile BN_ULONG sum;

            uint64_t ai_lo = (uint64_t)ai;
            uint64_t ai_hi = (uint64_t)(ai >> 64);
            uint64_t bi_lo = (uint64_t)bi;
            uint64_t bi_hi = (uint64_t)(bi >> 64);

            uint64_t sum_lo = ai_lo + bi_lo + (uint64_t)carry;
            uint64_t carry_lo = (sum_lo < ai_lo) || (carry && sum_lo == ai_lo);

            uint64_t sum_hi = ai_hi + bi_hi + carry_lo;
            carry = (sum_hi < ai_hi) || (carry_lo && sum_hi == ai_hi) ? 1 : 0;

            sum = ((BN_ULONG)sum_hi << 64) | sum_lo;
            result->d[i] = sum;
            __threadfence();  // Ensure global visibility of each word
        }

        if (carry > 0 && max_top < MAX_BIGNUM_SIZE - 1) {
            result->d[max_top + 1] = carry;
            max_top++;
        }

        // result->top = max_top + 1;
        result->top = find_top_optimized(result, max_top+1);
        __threadfence();  // Final memory barrier
    }
#else
    __device__ void absolute_add(BIGNUM *result, const BIGNUM *a, const BIGNUM *b) {
        // if (a->top != find_top(a)) printf("err: absolute_add: a->top != find_top(a)\n"); // no errors has been found
        // if (b->top != find_top(b)) printf("err: absolute_add: b->top != find_top(b)\n");
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
            
            // Calculate sum and carry
            BN_ULONG sum = ai + bi + carry;

            // Store result
            result->d[i] = sum; // No need for masking as BN_ULONG is already the correct size

            // Calculate carry
            carry = (sum < ai) || (carry > 0 && sum == ai) ? 1 : 0;
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
        result->top = find_top_optimized(result, max_top+1);
    }
#endif

__device__ void absolute_subtract(BIGNUM *result, const BIGNUM *a, const BIGNUM *b) {

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

    // // Normalize the result (remove leading zeros)
    // while (result->top > 0 && result->d[result->top - 1] == 0) {
    //     result->top--;
    // }

    // // If the result is zero, ensure top is set to 1 and d[0] is 0
    // if (result->top == 0) {
    //     result->top = 1;
    //     result->d[0] = 0;
    // }
    result->top = find_top_optimized(result, max_top);
}

__device__ bool bn_sub(BIGNUM *result, const BIGNUM *a, const BIGNUM *b) {
    #ifdef function_profiler
        unsigned long long start_time = clock64();
    #endif
    // If one is negative and the other is positive, it's essentially an addition.
    if (a->neg != b->neg) {
        result->neg = a->neg; // The sign will be the same as the sign of 'a'.
        absolute_add(result, a, b); // Perform the addition of magnitudes here because signs are different.
        #ifdef function_profiler
            record_function(FN_BN_SUB, start_time);
        #endif
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
    #ifdef function_profiler
        record_function(FN_BN_SUB, start_time);
    #endif
    return true;
}

__device__ bool bn_sub_from_div(BIGNUM *result, const BIGNUM *a, const BIGNUM *b) {
    #ifdef function_profiler
        unsigned long long start_time = clock64();
    #endif
    // If one is negative and the other is positive, it's essentially an addition.
    if (a->neg != b->neg) {
        result->neg = a->neg; // The sign will be the same as the sign of 'a'.
        absolute_add(result, a, b); // Perform the addition of magnitudes here because signs are different.
        #ifdef function_profiler
            record_function(FN_BN_SUB_FROM_DIV, start_time);
        #endif
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
    #ifdef function_profiler
        record_function(FN_BN_SUB_FROM_DIV, start_time);
    #endif
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

__device__ bool bn_add(BIGNUM *result, const BIGNUM *a, const BIGNUM *b) {
    #ifdef function_profiler
        unsigned long long start_time = clock64();
    #endif
    #ifdef debug_print
        printf("++ bn_add ++\n");
        bn_print(">> a: ", a);
        // printf(">> a->top: %d\n", a->top);
        // printf(">> a->neg: %d\n", a->neg);
        bn_print(">> b: ", b);
        // printf(">> b->top: %d\n", b->top);
        // printf(">> b->neg: %d\n", b->neg);
        // bn_print(">> result: ", result);
    #endif
    init_zero(result);
    unsigned char max_top = max(a->top, b->top);

    if (a->neg == b->neg) {
        // Both numbers have the same sign, so we can directly add them.
        absolute_add(result, a, b);
        // bn_print("absolute_add >> result: ", result); // <<== printing this result DOES NOT leads to correct answer
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
    // result->top = find_top_optimized(result, max_top + 1);
    #ifdef debug_print
        printf(">> result: ");
        bn_print("", result);
        printf("-- bn_add --\n");
    #endif
    #ifdef function_profiler
        record_function(FN_BN_ADD, start_time);
    #endif
    return true;
}

__device__ int bn_div(BIGNUM *a, BIGNUM *b, const BIGNUM *q, const BIGNUM *r);
__device__ void bn_mul(const BIGNUM *a, const BIGNUM *b, BIGNUM *product);

__device__ void set_bn(BIGNUM *dest, const BIGNUM *src) {
    // debug_printf("set_bn 0\n");
    // update src->top
    // src->top = find_top(src);
    #ifdef debug_top
        if (src->top != find_top(src)) printf("### ERROR: set_bn: src->top != find_top(src)\n");
    #endif
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

__device__ void mul64x64(uint64_t a, uint64_t b, uint64_t *hi, uint64_t *lo) {
    uint64_t a_low = (uint32_t)a;
    uint64_t a_high = a >> 32;
    uint64_t b_low = (uint32_t)b;
    uint64_t b_high = b >> 32;

    uint64_t res_low = a_low * b_low;
    uint64_t res_mid1 = a_low * b_high;
    uint64_t res_mid2 = a_high * b_low;
    uint64_t res_high = a_high * b_high;

    uint64_t carry = (res_low >> 32) + (uint32_t)res_mid1 + (uint32_t)res_mid2;
    uint64_t mid_high = (res_mid1 >> 32) + (res_mid2 >> 32) + (carry >> 32);

    *lo = (res_low & 0xFFFFFFFFULL) | ((carry & 0xFFFFFFFFULL) << 32);
    *hi = res_high + mid_high;
}

__device__ void bn_mul_64_ok(const BIGNUM *a, const BIGNUM *b, BIGNUM *product) {
    // Initialize product
    init_zero(product);

    #ifdef BN_128
        // Convert 128-bit BN_ULONGs to arrays of 64-bit words
        const int a_words = a->top * 2; // Since each BN_ULONG is 128 bits
        const int b_words = b->top * 2;
        uint64_t a_array[MAX_BIGNUM_SIZE * 2] = {0};
        uint64_t b_array[MAX_BIGNUM_SIZE * 2] = {0};
        uint64_t result_array[MAX_BIGNUM_SIZE * 4] = {0};

        // Expand 'a' into 'a_array'
        for (int i = 0; i < a->top; ++i) {
            a_array[2 * i] = (uint64_t)(a->d[i] & 0xFFFFFFFFFFFFFFFFULL); // Lower 64 bits
            a_array[2 * i + 1] = (uint64_t)(a->d[i] >> 64);               // Upper 64 bits
        }

        // Expand 'b' into 'b_array'
        for (int i = 0; i < b->top; ++i) {
            b_array[2 * i] = (uint64_t)(b->d[i] & 0xFFFFFFFFFFFFFFFFULL); // Lower 64 bits
            b_array[2 * i + 1] = (uint64_t)(b->d[i] >> 64);               // Upper 64 bits
        }

        // Perform multiplication using 64-bit arithmetic
        for (int i = 0; i < a_words; ++i) {
            uint64_t ai = a_array[i];
            uint64_t carry = 0;
            for (int j = 0; j < b_words; ++j) {
                uint64_t bj = b_array[j];
                uint64_t hi, lo;
                mul64x64(ai, bj, &hi, &lo);

                // Add lo to result_array[i + j] with carry
                uint64_t sum = result_array[i + j];
                uint64_t carry_out = 0;

                sum += lo;
                if (sum < lo) carry_out += 1;

                sum += carry;
                if (sum < carry) carry_out += 1;

                result_array[i + j] = sum;

                carry = hi + carry_out;
            }
            // Add remaining carry
            result_array[i + b_words] += carry;
        }

        // Convert result_array back to 128-bit BN_ULONGs
        int product_words = a_words + b_words;
        int product_top = (product_words + 1) / 2; // Ceiling division

        for (int i = 0; i < product_top; ++i) {
            uint64_t lo = result_array[2 * i];
            uint64_t hi = (2 * i + 1 < product_words) ? result_array[2 * i + 1] : 0;
            product->d[i] = ((BN_ULONG)hi << 64) | lo;
        }

        // Update 'top' and 'neg' fields
        product->top = find_top_optimized(product, product_top);
        product->neg = a->neg ^ b->neg;
    #else
        // Existing BN_64 implementation remains unchanged
    #endif

    // Optionally print the product
    bn_print("<< product: ", product);
}

__device__ int bn_bit_length(const BIGNUM *a) {
    if (a->top == 0) return 0;
    
    int bit_length = (a->top - 1) * BN_ULONG_NUM_BITS;
    BN_ULONG top_word = a->d[a->top - 1];
    
    while (top_word) {
        top_word >>= 1;
        bit_length++;
    }
    
    return bit_length;
}

__device__ void bn_mul(const BIGNUM *a, const BIGNUM *b, BIGNUM *product) {
    #ifdef function_profiler
        unsigned long long start_time = clock64();
    #endif
    #ifdef debug_print
        printf("++ bn_mul ++\n");
        printf("BN_ULONG_NUM_BITS: %d\n", BN_ULONG_NUM_BITS);
        bn_print(">> a: ", a);
        bn_print(">> b: ", b);
    #endif
    init_zero(product);
    #ifdef BN_128
        // Not efficient for my case
        // if (a->top == 1 and b->top == 1) {
        //     int a_bit_len = bn_bit_length(a);
        //     int b_bit_len = bn_bit_length(b);
        //     int product_bit_len = a_bit_len + b_bit_len;
        //     if (product_bit_len <= BN_ULONG_NUM_BITS) {
        //         // The product can fit in a single word
        //         product->d[0] = a->d[0] * b->d[0];
        //         product->top = 1;
        //         product->neg = a->neg ^ b->neg;
        //         record_function(FN_BN_MUL, start_time);
        //         return;
        //     }
        // }
        // Multiply the numbers treating them as arrays of 64-bit words
        const unsigned char a_words = a->top * 2; // Since each BN_ULONG is 128 bits (2 * 64 bits)
        const unsigned char b_words = b->top * 2;
        uint64_t a_array[MAX_BIGNUM_SIZE * 2] = {0};
        uint64_t b_array[MAX_BIGNUM_SIZE * 2] = {0};
        uint64_t result_array[MAX_BIGNUM_SIZE * 4] = {0};

        // Expand a into a_array
        for (unsigned char i = 0; i < a->top; ++i) {
            a_array[i * 2] = (uint64_t)(a->d[i]);
            a_array[i * 2 + 1] = (uint64_t)(a->d[i] >> 64);
        }

        // Expand b into b_array
        for (unsigned char i = 0; i < b->top; ++i) {
            b_array[i * 2] = (uint64_t)(b->d[i]);
            b_array[i * 2 + 1] = (uint64_t)(b->d[i] >> 64);
        }
        // char i = (char)max(a->top, b->top);
        // while (i > 0) {
        //     --i;
        //     if (i < a->top) {
        //         a_array[i * 2] = (uint64_t)(a->d[i]);
        //         a_array[i * 2 + 1] = (uint64_t)(a->d[i] >> 64);
        //     }
        //     if (i < b->top) {
        //         b_array[i * 2] = (uint64_t)(b->d[i]);
        //         b_array[i * 2 + 1] = (uint64_t)(b->d[i] >> 64);
        //     }
        // }

        unsigned __int128 temp;
        uint64_t carry;
        // Multiply the arrays
        for (unsigned char i = 0; i < a_words; ++i) {
            carry = 0;
            for (unsigned char j = 0; j < b_words; ++j) {
                // unsigned __int128 temp = (unsigned __int128)a_array[i] * b_array[j] + result_array[i + j] + carry;
                temp = (unsigned __int128)a_array[i] * b_array[j];
                temp += result_array[i + j];
                temp += carry;
                result_array[i + j] = (uint64_t)temp;
                carry = (uint64_t)(temp >> 64);
            }
            result_array[i + b_words] += carry;
        }

        // Convert result_array back into product->d
        unsigned char product_words = a_words + b_words;
        unsigned char product_top = (product_words + 1) / 2;
        for (unsigned char i = 0; i < product_top; ++i) {
            uint64_t lo = result_array[i * 2];
            uint64_t hi = result_array[i * 2 + 1];
            product->d[i] = ((unsigned __int128)hi << 64) | lo;
        }
        product->top = find_top_optimized(product, product_top);
        #ifdef debug_top
            if (product->top > MAX_BIGNUM_SIZE) {
                printf("### bn_mul ERROR: product->top > MAX_BIGNUM_SIZE\n");
            }
        #endif
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
        // Update the top
        product->top = a->top + b->top;
        while (product->top > 1 && product->d[product->top - 1] == 0) {
            product->top--;
        }
    #endif
    // Set the sign
    product->neg = a->neg ^ b->neg;
    #ifdef debug_print
        bn_print("<< product: ", product);
        printf("-- bn_mul --\n");
    #endif
    #ifdef function_profiler
        record_function(FN_BN_MUL, start_time);
    #endif
}

__device__ void bn_mul_from_div(const BIGNUM *a, const BIGNUM *b, BIGNUM *product, const bool absolute) {
    #ifdef function_profiler
        unsigned long long start_time = clock64();
    #endif
    #ifdef debug_print
        printf("++ bn_mul ++\n");
        printf("BN_ULONG_NUM_BITS: %d\n", BN_ULONG_NUM_BITS);
        bn_print(">> a: ", a);
        bn_print(">> b: ", b);
    #endif
    init_zero(product);
    #ifdef BN_128
        // Not efficient for my case
        // if (a->top == 1 and b->top == 1) {
        //     int a_bit_len = bn_bit_length(a);
        //     int b_bit_len = bn_bit_length(b);
        //     int product_bit_len = a_bit_len + b_bit_len;
        //     if (product_bit_len <= BN_ULONG_NUM_BITS) {
        //         // The product can fit in a single word
        //         product->d[0] = a->d[0] * b->d[0];
        //         product->top = 1;
        //         product->neg = a->neg ^ b->neg;
        //         record_function(FN_BN_MUL, start_time);
        //         return;
        //     }
        // }
        // Multiply the numbers treating them as arrays of 64-bit words
        const unsigned char a_words = a->top * 2; // Since each BN_ULONG is 128 bits (2 * 64 bits)
        const unsigned char b_words = b->top * 2;
        uint64_t a_array[MAX_BIGNUM_SIZE * 2] = {0};
        uint64_t b_array[MAX_BIGNUM_SIZE * 2] = {0};
        uint64_t result_array[MAX_BIGNUM_SIZE * 4] = {0};

        // Expand a into a_array
        for (unsigned char i = 0; i < a->top; ++i) {
            a_array[i * 2] = (uint64_t)(a->d[i]);
            a_array[i * 2 + 1] = (uint64_t)(a->d[i] >> 64);
        }

        // Expand b into b_array
        for (unsigned char i = 0; i < b->top; ++i) {
            b_array[i * 2] = (uint64_t)(b->d[i]);
            b_array[i * 2 + 1] = (uint64_t)(b->d[i] >> 64);
        }
        // char i = (char)max(a->top, b->top);
        // while (i > 0) {
        //     --i;
        //     if (i < a->top) {
        //         a_array[i * 2] = (uint64_t)(a->d[i]);
        //         a_array[i * 2 + 1] = (uint64_t)(a->d[i] >> 64);
        //     }
        //     if (i < b->top) {
        //         b_array[i * 2] = (uint64_t)(b->d[i]);
        //         b_array[i * 2 + 1] = (uint64_t)(b->d[i] >> 64);
        //     }
        // }

        unsigned __int128 temp;
        uint64_t carry;
        // Multiply the arrays
        for (unsigned char i = 0; i < a_words; ++i) {
            carry = 0;
            for (unsigned char j = 0; j < b_words; ++j) {
                // unsigned __int128 temp = (unsigned __int128)a_array[i] * b_array[j] + result_array[i + j] + carry;
                temp = (unsigned __int128)a_array[i] * b_array[j];
                temp += result_array[i + j];
                temp += carry;
                result_array[i + j] = (uint64_t)temp;
                carry = (uint64_t)(temp >> 64);
            }
            result_array[i + b_words] += carry;
        }

        // Convert result_array back into product->d
        unsigned char product_words = a_words + b_words;
        unsigned char product_top = (product_words + 1) / 2;
        for (unsigned char i = 0; i < product_top; ++i) {
            uint64_t lo = result_array[i * 2];
            uint64_t hi = result_array[i * 2 + 1];
            product->d[i] = ((unsigned __int128)hi << 64) | lo;
        }
        product->top = find_top_optimized(product, product_top);
        #ifdef debug_top
            if (product->top > MAX_BIGNUM_SIZE) {
                printf("### bn_mul ERROR: product->top > MAX_BIGNUM_SIZE\n");
            }
        #endif
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
        // Update the top
        product->top = a->top + b->top;
        while (product->top > 1 && product->d[product->top - 1] == 0) {
            product->top--;
        }
    #endif
    // Set the sign
    if (!absolute) product->neg = a->neg ^ b->neg;
    #ifdef debug_print
        bn_print("<< product: ", product);
        printf("-- bn_mul --\n");
    #endif
    #ifdef function_profiler
        record_function(FN_BN_MUL_FROM_DIV, start_time);
    #endif
}

__device__ int bn_mod(BIGNUM *r, const BIGNUM *a, const BIGNUM *n) {
    // r: Remainder (updated)
    // a: Dividend
    // n: Modulus
    bool debug = 0;
    if (debug) {
        printf("++ bn_mod ++\n");
        bn_print(">> r: ", r);
        bn_print(">> a: ", a);
        bn_print(">> n: ", n);
    }

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
            #ifdef debug_bn_copy
                printf("bn_mod: bn_copy(tmp, r)\n");
            #endif
            // copy tmp to r
            bn_copy(r, &tmp);
        } else {
            if (debug) printf("d is not negative\n");
            result = bn_add(&tmp, r, n); // tmp = r + n            
            if (!result) {
                return 0;
            }
            #ifdef debug_bn_copy
                printf("bn_mod: bn_copy(tmp, r)\n");
            #endif
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

__device__ bool bn_is_zero(const BIGNUM *a) {
    #ifdef debug_top
        if (a->top != find_top(a)) printf("### ERROR: bn_is_zero: a->top (%d) != find_top(a) (%d)\n", a->top, find_top(a));
    #endif
    for (int i = 0; i < a->top; ++i) {
        if (a->d[i] != 0) {
            return false;
        }
    }
    return true;
}

__device__ bool bn_is_one(const BIGNUM *a) {
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

    #ifdef debug_top
        if (bn->top != find_top(bn)) {
            if (bn->top != find_top(bn)) printf("### ERROR: bn_set_word: bn->top (%d) != find_top(bn) (%d)\n", bn->top, find_top(bn));
        }
    #endif

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

__device__ int bn_div(BIGNUM *bn_quotient, BIGNUM *bn_remainder, const BIGNUM *bn_dividend, const BIGNUM *bn_divisor)
{
    #ifdef function_profiler
        unsigned long long start_time = clock64();
    #endif
    #ifdef debug_print
        // printf("++ bn_div ++\n");
        // bn_print(">> bn_dividend: ", bn_dividend);
        // bn_print(">> bn_divisor: ", bn_divisor);
    #endif
    // printf("++ bn_div ++\n");
    // bn_print_no_fuse(">> bn_dividend: ", bn_dividend);
    // bn_print_no_fuse(">> bn_divisor: ", bn_divisor);

    

    unsigned char divs_max_top = max(bn_dividend->top, bn_divisor->top);
    
    // perform classical div_mod if only single word
    if (divs_max_top == 1) {
        // printf("divs_max_top == 1\n");
        BN_ULONG dividend = bn_dividend->d[0];
        BN_ULONG divisor = bn_divisor->d[0];
        BN_ULONG quotient = dividend / divisor;
        BN_ULONG remainder = dividend % divisor;
        bn_quotient->d[0] = quotient;
        bn_remainder->d[0] = remainder;
        bn_quotient->top = (quotient == 0) ? 0 : 1;
        bn_remainder->top = (remainder == 0) ? 0 : 1;
        bn_quotient->neg = bn_dividend->neg ^ bn_divisor->neg;
        bn_remainder->neg = bn_dividend->neg;
        #ifdef function_profiler
            record_function(FN_BN_DIV, start_time);
        #endif
        return 1;
    }

    // Store signs and work with absolute values
    BIGNUM abs_dividend;
    init_zero(&abs_dividend);

    // Copy absolute values
    for (int i = 0; i < divs_max_top; i++) {
        abs_dividend.d[i] = bn_dividend->d[i];
    }
    abs_dividend.neg = 0;
    abs_dividend.top = bn_dividend->top;

    // Initialize quotient and remainder
    init_zero(bn_quotient);
    init_zero(bn_remainder);

    // Handle special cases: Disabled for performance reasons
    // if (bn_cmp(&abs_dividend, &abs_divisor) == 0) {
    //     bn_quotient->d[0] = 1;
    //     bn_quotient->top = 1;
    //     bn_quotient->neg = (dividend_neg != divisor_neg);
    //     // printf("abs_dividend == abs_divisor. Quotient = 1\n");
    //     #ifdef function_profiler
    //         record_function(FN_BN_DIV, start_time);
    //     #endif
    //     return 1;
    // }
    // Perform long division
    BIGNUM current_dividend;
    init_zero(&current_dividend);
    char dividend_size = abs_dividend.top;

    for (int i = dividend_size - 1; i >= 0; i--) {
        // Shift current_dividend left by one word and add next word of dividend
        left_shift(&current_dividend, BN_ULONG_NUM_BITS);
        // if (bn_cmp(&abs_dividend, bn_dividend) != 0) {
        //     printf("[%d] dividend divergence:\n", i);
        //     bn_print_no_fuse("abs_dividend: ", &abs_dividend);
        //     bn_print_no_fuse("bn_dividend: ", bn_dividend);
        // }
        current_dividend.d[0] = abs_dividend.d[i];
        // current_dividend.d[0] = bn_dividend->d[i];

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

            // bn_mul(&abs_divisor, &temp, &product);
            bn_mul_from_div(bn_divisor, &temp, &product, true);

            if (bn_cmp(&product, &current_dividend) <= 0) {
                q = mid;
                left = mid + 1;
            } else {
                right = mid - 1;
            }
            // printf("[%d] ", i);
            // bn_print_no_fuse("bn_dividend: ", bn_dividend);
        }

        // Add quotient digit to result
        left_shift(bn_quotient, BN_ULONG_NUM_BITS);
        bn_quotient->d[0] |= q;

        // Subtract q * divisor from current_dividend
        BIGNUM temp, product;
        init_zero(&temp);
        init_zero(&product);
        temp.d[0] = q;
        temp.top = 1;

        // bn_mul(&abs_divisor, &temp, &product);
        bn_mul_from_div(bn_divisor, &temp, &product, true);

        // bn_sub(&current_dividend, &current_dividend, &product);
        bn_sub_from_div(&current_dividend, &current_dividend, &product);
    }

    // Set remainder
    for (int i = 0; i < current_dividend.top; i++) {
        bn_remainder->d[i] = current_dividend.d[i];
    }

    // Apply correct signs
    bn_quotient->neg = bn_dividend->neg ^ bn_divisor->neg;
    bn_remainder->neg = bn_dividend->neg;

    // Normalize results
    bn_quotient->top = find_top_optimized(bn_quotient, divs_max_top);
    bn_remainder->top = find_top_optimized(bn_remainder, divs_max_top);
    #ifdef debug_print
        // bn_print("<< bn_quotient: ", bn_quotient);
        // bn_print("<< bn_remainder: ", bn_remainder);
        // printf("-- bn_div --\n");
    #endif
    #ifdef function_profiler
        record_function(FN_BN_DIV, start_time);
    #endif
    return 1;
}