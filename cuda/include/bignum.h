#include <limits.h>
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include "function_profiling.h"

// #define BN_128
// #define debug_print
// #define debug_bn_copy
// #define debug_top
// #define function_profiler
// #define use_jacobian_coordinates
#define use_montgomery_ec_point_multiplication

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
    char top;
    bool neg;
} BIGNUM_CUDA;

typedef struct ec_group_st_cuda {
    BIGNUM_CUDA field;  // Prime field modulus p
    BIGNUM_CUDA a;      // Curve parameter a
    BIGNUM_CUDA b;      // Curve parameter b
    BIGNUM_CUDA order;  // Order of the base point
} EC_GROUP_CUDA;

// Define the number of bits in BN_ULONG
#define BN_BITS2 (sizeof(BN_ULONG) * 8)  // This will be 64
// #define TABLE_SIZE 32 // Maximum precomputation table size for sliding windows
// Helper macros for word operations
#define WORD_BITS BN_ULONG_NUM_BITS
#define WORD_MASK ((BN_ULONG)(-1))

// Initialize BIGNUM_CUDA to zero
#ifdef BN_128
    __device__ const BIGNUM_CUDA ZERO_BIGNUM = {
        {0},                  // d (will be properly initialized in init_zero)
        1,                    // top (char)
        0                    // neg (bool)
    };
#else
    __device__ const BIGNUM_CUDA ZERO_BIGNUM = {
        {0,0,0,0,0,0,0,0,0,0},                  // d (will be properly initialized in init_zero)
        1,                    // top (char)
        0                    // neg (bool)
    };
#endif

__device__ void init_zero(BIGNUM_CUDA *bn) {
    // *bn = ZERO_BIGNUM;
    for (int i = 0; i < MAX_BIGNUM_SIZE; i++) {
        bn->d[i] = 0;
    }
    bn->top = 1;
    bn->neg = 0;
}
__device__ void init_one(BIGNUM_CUDA *bn) {
    // Initialize the BIGNUM_CUDA to zero
    *bn = ZERO_BIGNUM;
    
    // Set the least significant word to 1
    bn->d[0] = 1;
    
    // Set the top to 1 (as there is one significant digit)
    bn->top = 1;
}

__device__ bool bn_add(BIGNUM_CUDA *result, const BIGNUM_CUDA *a, const BIGNUM_CUDA *b);
__device__ int bn_mod(BIGNUM_CUDA *r, const BIGNUM_CUDA *a, const BIGNUM_CUDA *n);
__device__ bool bn_is_zero(const BIGNUM_CUDA *a);

__device__ char find_top_cuda(const BIGNUM_CUDA *bn) {
    for (char i = MAX_BIGNUM_SIZE - 1; i >= 0; i--) {
        if (bn->d[i] != 0) {
            return i + 1;
        }
    }
    return 1;
}

__device__ char find_top_optimized(const BIGNUM_CUDA *bn, const char start_index) {
    const char start = start_index > MAX_BIGNUM_SIZE ? MAX_BIGNUM_SIZE : start_index;
    for (char i = start - 1; i >= 0; i--) {
        if (bn->d[i] != 0) {
            return i + 1;
        }
    }
    return 1;
}

__device__ void bn_print(const char* msg, const BIGNUM_CUDA* a) {
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
        printf("-");  // Handle the case where BIGNUM_CUDA is negative
    }
    for (int i = a->top - 1; i >= 0; i--) {
        // Print words up to top - 1 with appropriate formatting
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
    }
    printf("\n");
}

__device__ void bn_print_no_fuse(const char* msg, const BIGNUM_CUDA* a) {   
    #ifdef debug_top
        if (a->top != find_top(a)) printf("### ERROR: bn_print: a->top (%d) != find_top(a) (%d)\n", a->top, find_top(a));
    #endif
    printf("%s", msg);
    printf("[");
    if (a->neg) printf("-");
    else printf("+");
    printf("%d] ", a->top);
    if (a->neg) {
        printf("-");  // Handle the case where BIGNUM_CUDA is negative
    }
    for (char i = a->top - 1; i >= 0; i--) {
        // Print words up to top - 1 with appropriate formatting
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
    }
    printf("\n");
}

__device__ void print_as_hex(const uint8_t *data, const uint32_t len) {
    for (uint32_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

__device__ int bn_cmp(const BIGNUM_CUDA* a, const BIGNUM_CUDA* b) {
    // -1: a < b
    // 0: a == b
    // 1: a > b
    #ifdef debug_print
        printf("++ bn_cmp ++\n");
        bn_print(">> a: ", a);
        bn_print(">> b: ", b);
    #endif
    if (a->neg != b->neg) {
        #ifdef debug_print
            printf("a->neg != b->neg\n-- bn_cmp --\n");
        #endif
        return a->neg ? -1 : 1;
    }
    #ifdef debug_top
        if (a->top != find_top(a)) printf("### ERROR: bn_cmp: a->top != find_top(a)\n");
        if (b->top != find_top(b)) printf("### ERROR: bn_cmp: b->top != find_top(b)\n");
    #endif
    if (a->top != b->top) {
        #ifdef debug_print
            printf("a->top != b->top\n-- bn_cmp --\n");
        #endif
        return a->top > b->top ? 1 : -1;
    }

    for (int i = a->top - 1; i >= 0; i--) {
        if (a->d[i] != b->d[i]) {
            #ifdef debug_print
                printf("a->d[i] != b->d[i]\n-- bn_cmp --\n");
            #endif
            return a->d[i] > b->d[i] ? 1 : -1;
        }
    }
    #ifdef debug_print
        printf("default case\n-- bn_cmp --\n");
    #endif
    return 0;
}

__device__ int bn_cmp_abs(const BIGNUM_CUDA *a, const BIGNUM_CUDA *b) {
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

__device__ int bn_ucmp(const BIGNUM_CUDA *a, const BIGNUM_CUDA *b) {
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

// Helper function to perform a deep copy of BIGNUM_CUDA
__device__ void bn_copy(BIGNUM_CUDA * __restrict__ dest, const BIGNUM_CUDA *src) {
    init_zero(dest);
    char limit = (src->top < MAX_BIGNUM_SIZE) ? src->top : MAX_BIGNUM_SIZE;

    for (char i = 0; i < limit; i++) {
        dest->d[i] = src->d[i];
    }

    dest->neg = src->neg;
    dest->top = src->top;
}

#ifdef BN_128
    __device__ void absolute_add(BIGNUM_CUDA *result, const BIGNUM_CUDA *a, const BIGNUM_CUDA *b) {
        char max_top = max(a->top, b->top);
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
    __device__ void absolute_add(BIGNUM_CUDA *result, const BIGNUM_CUDA *a, const BIGNUM_CUDA *b) {
        // Determine the maximum size to iterate over
        char max_top = max(a->top, b->top);
        BN_ULONG carry = 0;

        char i;

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
                // Handle error: Result BIGNUM_CUDA doesn't have space for an additional word.
                // This should potentially be reported back to the caller.
                printf("absolute_add: Result BIGNUM_CUDA doesn't have space for an additional word.\n");
            }
        }
        result->top = find_top_optimized(result, max_top+1);
    }
#endif

__device__ void absolute_subtract(BIGNUM_CUDA *result, const BIGNUM_CUDA *a, const BIGNUM_CUDA *b) {

    char max_top = max(a->top, b->top);
    BN_ULONG borrow = 0;
    result->top = max_top;

    for (char i = 0; i < max_top; ++i) {
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

    result->top = find_top_optimized(result, max_top);
}

__device__ bool bn_sub(BIGNUM_CUDA *result, const BIGNUM_CUDA *a, const BIGNUM_CUDA *b) {
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

__device__ bool bn_sub_from_div(BIGNUM_CUDA *result, const BIGNUM_CUDA *a, const BIGNUM_CUDA *b) {
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

__device__ int absolute_compare(const BIGNUM_CUDA* a, const BIGNUM_CUDA* b) {
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

__device__ bool bn_add(BIGNUM_CUDA *result, const BIGNUM_CUDA *a, const BIGNUM_CUDA *b) {
    #ifdef function_profiler
        unsigned long long start_time = clock64();
    #endif
    #ifdef debug_print
        printf("++ bn_add ++\n");
        bn_print(">> a: ", a);
        bn_print(">> b: ", b);
    #endif
    init_zero(result);
    char max_top = max(a->top, b->top);

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

__device__ int bn_div(BIGNUM_CUDA *a, BIGNUM_CUDA *b, const BIGNUM_CUDA *q, const BIGNUM_CUDA *r);
__device__ void bn_mul(const BIGNUM_CUDA *a, const BIGNUM_CUDA *b, BIGNUM_CUDA *product);

__device__ void set_bn(BIGNUM_CUDA *dest, const BIGNUM_CUDA *src) {
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
        #ifdef debug_print
            printf("set_bn 1.%d\n", i);
        #endif
        dest->d[i] = src->d[i];
    }

    // Zero out any remaining entries in the array if the source 'top' is less than the dest 'dmax'
    for (int i = src->top; i < MAX_BIGNUM_SIZE; ++i) {
        #ifdef debug_print
            printf("set_bn 2.%d\n", i);
        #endif
        dest->d[i] = 0;
    }
    #ifdef debug_print
        printf("set_bn 3\n");
    #endif

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

__device__ void bn_mul_64_ok(const BIGNUM_CUDA *a, const BIGNUM_CUDA *b, BIGNUM_CUDA *product) {
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

__device__ int bn_bit_length(const BIGNUM_CUDA *a) {
    if (a->top == 0) return 0;
    
    int bit_length = (a->top - 1) * BN_ULONG_NUM_BITS;
    BN_ULONG top_word = a->d[a->top - 1];
    
    while (top_word) {
        top_word >>= 1;
        bit_length++;
    }
    
    return bit_length;
}

__device__ void bn_mul(const BIGNUM_CUDA *a, const BIGNUM_CUDA *b, BIGNUM_CUDA *product) {
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
        // Multiply the numbers treating them as arrays of 64-bit words
        const char a_words = a->top * 2; // Since each BN_ULONG is 128 bits (2 * 64 bits)
        const char b_words = b->top * 2;
        uint64_t a_array[MAX_BIGNUM_SIZE * 2] = {0};
        uint64_t b_array[MAX_BIGNUM_SIZE * 2] = {0};
        uint64_t result_array[MAX_BIGNUM_SIZE * 4] = {0};

        // Expand a into a_array
        for (char i = 0; i < a->top; ++i) {
            a_array[i * 2] = (uint64_t)(a->d[i]);
            a_array[i * 2 + 1] = (uint64_t)(a->d[i] >> 64);
        }

        // Expand b into b_array
        for (char i = 0; i < b->top; ++i) {
            b_array[i * 2] = (uint64_t)(b->d[i]);
            b_array[i * 2 + 1] = (uint64_t)(b->d[i] >> 64);
        }
        unsigned __int128 temp;
        uint64_t carry;
        // Multiply the arrays
        for (char i = 0; i < a_words; ++i) {
            carry = 0;
            for (char j = 0; j < b_words; ++j) {
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
        char product_words = a_words + b_words;
        char product_top = (product_words + 1) / 2;
        for (char i = 0; i < product_top; ++i) {
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

__device__ void bn_mul_from_div(const BIGNUM_CUDA *a, const BIGNUM_CUDA *b, BIGNUM_CUDA *product, const bool absolute) {
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
        if (a->top == 1 && b->top == 1) {
            int a_bit_len = bn_bit_length(a);
            int b_bit_len = bn_bit_length(b);
            int product_bit_len = a_bit_len + b_bit_len;
            if (product_bit_len <= BN_ULONG_NUM_BITS) {
                // The product can fit in a single word
                product->d[0] = (BN_ULONG)a->d[0] * b->d[0];
                product->top = 1;
                if (!absolute) product->neg = a->neg ^ b->neg;
                return;
            }
        }
        // Multiply the numbers treating them as arrays of 64-bit words
        const char a_words = a->top * 2; // Since each BN_ULONG is 128 bits (2 * 64 bits)
        const char b_words = b->top * 2;
        uint64_t a_array[MAX_BIGNUM_SIZE * 2] = {0};
        uint64_t b_array[MAX_BIGNUM_SIZE * 2] = {0};
        uint64_t result_array[MAX_BIGNUM_SIZE * 4] = {0};

        // Expand a into a_array
        for (char i = 0; i < a->top; ++i) {
            a_array[i * 2] = (uint64_t)(a->d[i]);
            a_array[i * 2 + 1] = (uint64_t)(a->d[i] >> 64);
        }

        // Expand b into b_array
        for (char i = 0; i < b->top; ++i) {
            b_array[i * 2] = (uint64_t)(b->d[i]);
            b_array[i * 2 + 1] = (uint64_t)(b->d[i] >> 64);
        }

        unsigned __int128 temp;
        uint64_t carry;
        // Multiply the arrays
        for (char i = 0; i < a_words; ++i) {
            carry = 0;
            for (char j = 0; j < b_words; ++j) {
                temp = (unsigned __int128)a_array[i] * b_array[j];
                temp += result_array[i + j];
                temp += carry;
                result_array[i + j] = (uint64_t)temp;
                carry = (uint64_t)(temp >> 64);
            }
            result_array[i + b_words] += carry;
        }

        // Convert result_array back into product->d
        char product_words = a_words + b_words;
        char product_top = (product_words + 1) / 2;
        for (char i = 0; i < product_top; ++i) {
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
        // Multiply in vanila way if top is less than 3
        if (a->top < 3 && b->top < 3) {
            int a_bit_len = bn_bit_length(a);
            int b_bit_len = bn_bit_length(b);
            int product_bit_len = a_bit_len + b_bit_len;
            if (product_bit_len <= BN_ULONG_NUM_BITS * 2) {
                // The product can fit in a single 128-bit word
                unsigned __int128 temp_a, temp_b;// = (unsigned __int128)a->d[0] * b->d[0];
                // first word of a
                temp_a = (unsigned __int128)a->d[0];
                // second word of a
                if (a->top > 1) {
                    temp_a += (unsigned __int128)a->d[1] << 64;
                }
                // first word of b
                temp_b = (unsigned __int128)b->d[0];
                // second word of b
                if (b->top > 1) {
                    temp_b += (unsigned __int128)b->d[1] << 64;
                }
                // Multiply the two 128-bit numbers
                unsigned __int128 temp = temp_a * temp_b;

                // Save the result in the product's d words
                product->d[0] = (BN_ULONG)temp;
                product->d[1] = (BN_ULONG)(temp >> 64);
                product->top = find_top_optimized(product, 2);
                if (!absolute) product->neg = a->neg ^ b->neg;
                #ifdef function_profiler
                    record_function(FN_BN_MUL_VANILA_2, start_time);
                #endif
                return;
            }
        }

        // Unroll loops if possible
        unsigned __int128 temp_product, temp_a, temp_b;

        for (int i = 0; i < a->top; i++) {
            BN_ULONG carry = 0;
            for (int j = 0; j < b->top; j++) {
                temp_a = a->d[i];
                temp_b = b->d[j];
                temp_product = temp_a * temp_b;
                temp_product += product->d[i + j];
                temp_product += carry;
                product->d[i + j] = (BN_ULONG)temp_product;
                carry = (BN_ULONG)(temp_product >> 64);
            }
            product->d[i + b->top] = carry;
        }
        // Update the top
        product->top = find_top_optimized(product, a->top + b->top);
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

__device__ int bn_mod(BIGNUM_CUDA *r, const BIGNUM_CUDA *a, const BIGNUM_CUDA *n) {
    // r: Remainder (updated)
    // a: Dividend
    // n: Modulus
    #ifdef debug_print
        printf("++ bn_mod ++\n");
        bn_print_no_fuse(">> r: ", r);
        bn_print_no_fuse(">> a: ", a);
        bn_print_no_fuse(">> n: ", n);
    #endif

    BIGNUM_CUDA q;
    init_zero(&q);

    // if (r == n) {
    if (bn_cmp(r, n) == 0) {
        printf("bn_mod: ERR_R_PASSED_INVALID_ARGUMENT");
        return 0;
    }
    if (!bn_div(&q, r, a, n)) {
        printf("bn_mod: bn_div failed\n");
        return 0;
    }

    BIGNUM_CUDA tmp;
    init_zero(&tmp);

    if (r->neg) {
        #ifdef debug_print
            printf("r is negative\n");
        #endif
        bool result;
        // If the remainder is negative, add the absolute value of the divisor
        if (n->neg) {
            #ifdef debug_print
                printf("d is negative\n");
            #endif
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
            #ifdef debug_top
                printf("d is not negative\n");
            #endif
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
    #ifdef debug_print
        bn_print_no_fuse("<< q: ", &q);
        bn_print_no_fuse("<< r (out): ", r);
        printf("-- bn_mod --\n");
    #endif
    return 1;
}

__device__ void mod_mul(BIGNUM_CUDA *a, BIGNUM_CUDA *b, BIGNUM_CUDA *mod, BIGNUM_CUDA *result) {
    BIGNUM_CUDA product;
    init_zero(&product);
    bn_mul(a, b, &product);
    bn_mod(&product, mod, result);
}

__device__ bool bn_is_zero(const BIGNUM_CUDA *a) {
    #ifdef debug_top
        if (a->top != find_top_cuda(a)) printf("### ERROR: bn_is_zero: a->top (%d) != find_top(a) (%d)\n", a->top, find_top_cuda(a));
    #endif
    for (int i = 0; i < a->top; ++i) {
        if (a->d[i] != 0) {
            return false;
        }
    }
    return true;
}

__device__ bool bn_is_one(const BIGNUM_CUDA *a) {
    // Assuming that BIGNUM_CUDA stores the number in an array 'd' of integers
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

__device__ void bn_set_word(BIGNUM_CUDA *bn, BN_ULONG word) {
    // Assuming d is a pointer to an array where the BIGNUM_CUDA's value is stored
    // and top is an integer representing the index of the most significant word + 1
    // Setting a BIGNUM_CUDA to a single-word value means that all other words are zero.

    #ifdef debug_top
        if (bn->top != find_top(bn)) {
            if (bn->top != find_top(bn)) printf("### ERROR: bn_set_word: bn->top (%d) != find_top(bn) (%d)\n", bn->top, find_top(bn));
        }
    #endif

    // Clear all words in the BIGNUM_CUDA
    for (int i = 0; i < MAX_BIGNUM_SIZE; ++i) {
        bn->d[i] = 0;
    }

    // Set the least significant word to the specified value
    bn->d[0] = word;

    // Update top to indicate that there's at least one significant digit
    bn->top = (word == 0) ? 0 : 1;

    // If using a sign flag, ensure the BIGNUM_CUDA is set to non-negative
    if (bn->top) {
        bn->neg = 0;
    }
}

__device__ void left_shift(BIGNUM_CUDA *a, int shift) {
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
    char potential_new_top = a->top + (shift + BN_ULONG_NUM_BITS - 1) / BN_ULONG_NUM_BITS;
    a->top = find_top_optimized(a, potential_new_top);
}

__device__ int bn_div(BIGNUM_CUDA *bn_quotient, BIGNUM_CUDA *bn_remainder, const BIGNUM_CUDA *bn_dividend, const BIGNUM_CUDA *bn_divisor)
{
    #ifdef function_profiler
        unsigned long long start_time = clock64();
    #endif
    #ifdef debug_print
        printf("++ bn_div ++\n");
        bn_print_no_fuse(">> bn_quotient: ", bn_quotient);
        bn_print_no_fuse(">> bn_remainder: ", bn_remainder);
        bn_print_no_fuse(">> bn_dividend: ", bn_dividend);
        bn_print_no_fuse(">> bn_divisor: ", bn_divisor);
    #endif
    char divs_max_top = max(bn_dividend->top, bn_divisor->top);
    
    // perform classical div_mod if only single word
    if (divs_max_top == 1) {
        BN_ULONG dividend = bn_dividend->d[0];
        BN_ULONG divisor = bn_divisor->d[0];
        BN_ULONG quotient = dividend / divisor;
        BN_ULONG remainder = dividend % divisor;
        bn_quotient->d[0] = quotient;
        bn_remainder->d[0] = remainder;
        bn_quotient->top = (quotient == 0) ? 0 : 1;
        // bn_remainder->top = (remainder == 0) ? 0 : 1;
        bn_remainder->top = find_top_optimized(bn_remainder, 2);
        bn_quotient->neg = bn_dividend->neg ^ bn_divisor->neg;
        bn_remainder->neg = bn_dividend->neg;
        #ifdef function_profiler
            record_function(FN_BN_DIV_VANILA_1, start_time);
        #endif
        return 1;
    }
    // TODO compare dividend, not divs_max_top
    else if (divs_max_top == 2) {
        // Divide in vanila way using 128-bit values if max top is 2:
        unsigned __int128 dividend, divisor;
        dividend = (unsigned __int128)bn_dividend->d[1] << 64 | bn_dividend->d[0];
        divisor = (unsigned __int128)bn_divisor->d[1] << 64 | bn_divisor->d[0];
        unsigned __int128 quotient = dividend / divisor;
        unsigned __int128 remainder = dividend % divisor;
        // first word of quotient
        bn_quotient->d[0] = (BN_ULONG)quotient;
        // second word of quotient
        bn_quotient->d[1] = (BN_ULONG)(quotient >> 64);
        bn_quotient->top = find_top_optimized(bn_quotient, 2);
        bn_quotient->neg = bn_dividend->neg ^ bn_divisor->neg;

        // first word of remainder
        bn_remainder->d[0] = (BN_ULONG)remainder;
        // second word of remainder
        bn_remainder->d[1] = (BN_ULONG)(remainder >> 64);
        bn_remainder->top = find_top_optimized(bn_remainder, 2);
        bn_remainder->neg = bn_dividend->neg;
        #ifdef function_profiler
            record_function(FN_BN_DIV_VANILA_2, start_time);
        #endif
        return 1;
    }
    BIGNUM_CUDA abs_dividend;
    init_zero(&abs_dividend);
    // Copy absolute values
    for (int i = 0; i < bn_dividend->top; i++) {
        abs_dividend.d[i] = bn_dividend->d[i];
    }
    abs_dividend.top = bn_dividend->top;   

    // Store signs and work with absolute values
    abs_dividend.neg = 0;

    // Initialize quotient and remainder
    init_zero(bn_quotient);
    init_zero(bn_remainder);
    // Perform long division
    BIGNUM_CUDA current_dividend;
    init_zero(&current_dividend);
    char dividend_size = abs_dividend.top;

    for (int i = dividend_size - 1; i >= 0; i--) {
        // Shift current_dividend left by one word and add next word of dividend
        left_shift(&current_dividend, BN_ULONG_NUM_BITS);
        current_dividend.d[0] = abs_dividend.d[i];
        // Find quotient digit
        BN_ULONG q = 0;
        unsigned __int128 left = 0, right = BN_ULONG_MAX;
        while (left <= right) {
            unsigned __int128 mid = left + (right - left) / 2;
            BIGNUM_CUDA temp, product;
            init_zero(&temp);
            init_zero(&product);
            temp.d[0] = mid;
            temp.top = 1;
            bn_mul_from_div(bn_divisor, &temp, &product, true);

            if (bn_cmp(&product, &current_dividend) <= 0) {
                q = mid;
                left = mid + 1;
            } else {
                right = mid - 1;
            }            
        }

        // Add quotient digit to result
        left_shift(bn_quotient, BN_ULONG_NUM_BITS);
        bn_quotient->d[0] |= q;

        // Subtract q * divisor from current_dividend
        BIGNUM_CUDA temp, product;
        init_zero(&temp);
        init_zero(&product);
        temp.d[0] = q;
        temp.top = 1;

        bn_mul_from_div(bn_divisor, &temp, &product, true);
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
        bn_print("<< bn_quotient: ", bn_quotient);
        bn_print("<< bn_remainder: ", bn_remainder);
        printf("-- bn_div --\n");
    #endif
    #ifdef function_profiler
        record_function(FN_BN_DIV, start_time);
    #endif
    return 1;
}

__device__ int bn_mod_sqr(BIGNUM_CUDA *r, const BIGNUM_CUDA *a, const BIGNUM_CUDA *m) {
    BIGNUM_CUDA tmp;
    init_zero(&tmp);
    bn_mul(a, a, &tmp); // a * b = product
    return bn_mod(r, &tmp, m); // result = a % m
}

__device__ int bn_mod_mul(BIGNUM_CUDA *r, const BIGNUM_CUDA *a, const BIGNUM_CUDA *b, const BIGNUM_CUDA *m) {
    BIGNUM_CUDA tmp;
    init_zero(&tmp);
    bn_mul(a, b, &tmp); // a * b = product
    BIGNUM_CUDA r_tmp;
    init_zero(&r_tmp);
    int ret = bn_mod(&r_tmp, &tmp, m); // result = tmp % m
    bn_copy(r, &r_tmp);
    return ret;
}

__device__ int bn_mod_lshift(BIGNUM_CUDA *r, BIGNUM_CUDA *a, int shift, const BIGNUM_CUDA *p) {
    BIGNUM_CUDA temp;
    init_zero(&temp);
    left_shift(a, shift);
    bn_mod(r, a, p);
    return 1;
}

__device__ int bn_mod_add(BIGNUM_CUDA *result, const BIGNUM_CUDA *a, const BIGNUM_CUDA *b, const BIGNUM_CUDA *n) {
    bn_add(result, a, b);
    BIGNUM_CUDA tmp;
    init_zero(&tmp);
    bn_copy(&tmp, result); // dest << src
    bn_mod(result, &tmp, n); // result = a mod n
    return 1;
}

__device__ int bn_mod_sub(BIGNUM_CUDA *result, const BIGNUM_CUDA *a, const BIGNUM_CUDA *b, const BIGNUM_CUDA *n) {
    bn_sub(result, a, b);
    if (result->neg) {
        BIGNUM_CUDA tmp;
        init_zero(&tmp);
        bn_copy(&tmp, result); // dest << src
        bn_add(result, &tmp, n); // result = a + b
        result->neg = 0;
    }
    return 1;
}

// Computes the extended GCD of a and b
// Returns gcd(a,b) and finds x,y such that ax + by = gcd(a,b)
// If x or y is NULL, that coefficient is not computed
__device__ void bn_extended_gcd(const BIGNUM_CUDA *a, const BIGNUM_CUDA *b, 
                               BIGNUM_CUDA *x, BIGNUM_CUDA *y, BIGNUM_CUDA *gcd) {
    BIGNUM_CUDA old_r, r;
    BIGNUM_CUDA old_s, s;
    BIGNUM_CUDA old_t, t;
    BIGNUM_CUDA quotient, temp1, temp2;
    
    // Initialize all temporary variables
    init_zero(&old_r);
    init_zero(&r);
    init_zero(&old_s);
    init_zero(&s);
    init_zero(&old_t);
    init_zero(&t);
    init_zero(&quotient);
    init_zero(&temp1);
    init_zero(&temp2);
    
    // Initialize starting values
    bn_copy(&old_r, a);     // old_r = a
    bn_copy(&r, b);         // r = b
    init_one(&old_s);       // old_s = 1
    init_zero(&s);          // s = 0
    init_zero(&old_t);      // old_t = 0
    init_one(&t);           // t = 1
    
    // While r ≠ 0
    while (!bn_is_zero(&r)) {
        // Compute quotient = old_r / r
        init_zero(&quotient);
        init_zero(&temp1);
        bn_div(&quotient, &temp1, &old_r, &r);
        
        // temp1 = quotient * r
        init_zero(&temp1);
        bn_mul(&quotient, &r, &temp1);
        
        // temp2 = old_r - temp1 = old_r - quotient * r
        init_zero(&temp2);
        bn_sub(&temp2, &old_r, &temp1);
        
        // old_r = r
        bn_copy(&old_r, &r);
        
        // r = temp2
        bn_copy(&r, &temp2);
        
        // Same for s
        // temp1 = quotient * s
        init_zero(&temp1);
        bn_mul(&quotient, &s, &temp1);
        
        // temp2 = old_s - temp1
        init_zero(&temp2);
        bn_sub(&temp2, &old_s, &temp1);
        
        // old_s = s
        bn_copy(&old_s, &s);
        
        // s = temp2
        bn_copy(&s, &temp2);
        
        // Same for t
        // temp1 = quotient * t
        init_zero(&temp1);
        bn_mul(&quotient, &t, &temp1);
        
        // temp2 = old_t - temp1
        init_zero(&temp2);
        bn_sub(&temp2, &old_t, &temp1);
        
        // old_t = t
        bn_copy(&old_t, &t);
        
        // t = temp2
        bn_copy(&t, &temp2);
    }
    
    // Set outputs
    if (gcd != NULL) {
        bn_copy(gcd, &old_r);
    }
    
    if (x != NULL) {
        bn_copy(x, &old_s);
        // Adjust sign if necessary
        if (a->neg) {
            x->neg = !x->neg;
        }
    }
    
    if (y != NULL) {
        bn_copy(y, &old_t);
        // Adjust sign if necessary
        if (b->neg) {
            y->neg = !y->neg;
        }
    }
}

__device__ bool bn_mod_inverse(BIGNUM_CUDA *result, const BIGNUM_CUDA *a, const BIGNUM_CUDA *n) {
    #ifdef debug_print
        printf("++ bn_mod_inverse ++\n");
        bn_print(">> a: ", a);
        bn_print(">> n: ", n);
    #endif
    
    if (bn_is_one(n)) {
        return false;  // No modular inverse exists if modulus is 1
    }

    if (bn_is_one(a)) {
        // The modular inverse of 1 is 1
        init_one(result);
        return true;
    }

    BIGNUM_CUDA r;
    BIGNUM_CUDA nr;
    BIGNUM_CUDA t;
    BIGNUM_CUDA nt;
    BIGNUM_CUDA q;
    BIGNUM_CUDA tmp;
    BIGNUM_CUDA tmp2;
    BIGNUM_CUDA tmp3;

    init_zero(&r);
    init_zero(&nr);
    init_zero(&t);
    init_one(&nt);
    init_zero(&q);
    init_zero(&tmp);
    init_zero(&tmp2);
    init_zero(&tmp3);
    #ifdef debug_bn_copy
        printf("bn_mod_inverse: bn_copy(r, n)\n");
    #endif
    bn_copy(&r, n);
    bn_mod(&nr, a, n); // Compute non-negative remainder of 'a' modulo 'n'
    #ifdef debug_print
        unsigned int counter = 0;
    #endif
    while (!bn_is_zero(&nr)) {
        bn_div(&q, &tmp, &r, &nr); // Compute quotient and remainder
        #ifdef debug_bn_copy
            printf("bn_mod_inverse: bn_copy(tmp, nt)\n");
        #endif
        bn_copy(&tmp, &nt);
        bn_mul(&q, &nt, &tmp2); // tmp2 = q * nt
        init_zero(&tmp3);
        bn_sub(&tmp3, &t, &tmp2); // tmp3 = t - tmp2
        // if (tmp3.top!=find_top(&tmp3)) printf("*** hypotesis true: bn_sub top is not correct\n");
        #ifdef debug_bn_copy
            printf("bn_mod_inverse: bn_copy(nt, tmp3)\n");
        #endif
        bn_copy(&nt, &tmp3); // dst << src
        #ifdef debug_bn_copy
            printf("bn_mod_inverse: bn_copy(t, tmp)\n");
        #endif
        bn_copy(&t, &tmp);
        #ifdef debug_bn_copy
            printf("bn_mod_inverse: bn_copy(tmp, nr)\n");
        #endif
        bn_copy(&tmp, &nr);
        bn_mul(&q, &nr, &tmp2);
        init_zero(&tmp3);
        bn_sub(&tmp3, &r, &tmp2); // tmp3 = r - tmp2
        #ifdef debug_bn_copy
            printf("bn_mod_inverse: bn_copy(r, tmp3)\n");
        #endif
        bn_copy(&nr, &tmp3);
        #ifdef debug_bn_copy
            printf("bn_mod_inverse: bn_copy(r, tmp)\n");
        #endif
        bn_copy(&r, &tmp);        
        #ifdef debug_print
            counter++;
            printf("[%d] ", counter);
            bn_print(" t: ", &t);
        #endif
    }

    if (!bn_is_one(&r)) {
        init_zero(result);
        return false; // No modular inverse exists
    }

    if (t.neg != 0) {
        bn_add(&tmp2, &t, n); // tmp2 = t + n
        #ifdef debug_bn_copy
            printf("bn_mod_inverse: bn_copy(t, tmp2)\n");
        #endif
        bn_copy(&t, &tmp2);
    }
    #ifdef debug_bn_copy
        printf("bn_mod_inverse: bn_copy(result, t)\n");
    #endif
    bn_copy(result, &t);
    #ifdef debug_print
        bn_print("<< result: ", result);
        printf("-- bn_mod_inverse --\n");
    #endif
    return true;
}

// Montgomery multiplication ++
__device__ void bn_mod_neg(BIGNUM_CUDA *result, const BIGNUM_CUDA *n, const BIGNUM_CUDA *R) {
    // Compute -n mod R
    if (bn_cmp(n, R) < 0) {
        // If n < R, just subtract n from R
        bn_sub(result, R, n);
    } else {
        // If n >= R, first reduce n modulo R
        BIGNUM_CUDA tmp;
        init_zero(&tmp);
        bn_mod(&tmp, n, R);  // tmp = n mod R
        bn_sub(result, R, &tmp);  // result = R - (n mod R)
    }
}

__device__ bool compute_mont_nprime(BIGNUM_CUDA *n_prime, const BIGNUM_CUDA *n, const BIGNUM_CUDA *R) {
    #ifdef debug_top
        printf("++ compute_mont_nprime ++\n");
        bn_print_no_fuse(">> n: ", n);
        bn_print_no_fuse(">> R: ", R);
    #endif

    // Check for null pointers and invalid inputs
    if (bn_is_zero(n)) {
        printf("Error: modulus n cannot be zero\n");
        return false;
    }

    if (bn_is_zero(R)) {
        printf("Error: R cannot be zero\n");
        return false;
    }
    
    // Compute -n
    BIGNUM_CUDA neg_n;
    init_zero(&neg_n);
    bn_mod_neg(&neg_n, n, R);
    #ifdef debug_top
        bn_print_no_fuse("neg_n: ", &neg_n);
    #endif

    // Compute (-n)^(-1) mod R using bn_mod_inverse
    return bn_mod_inverse(n_prime, &neg_n, R);
    
    // Result is already reduced modulo R since bn_mod_inverse handles this
    // No need for additional modulo operation
}

// Helper function to verify if two numbers are coprime
__device__ bool are_coprime(const BIGNUM_CUDA *a, const BIGNUM_CUDA *b) {
    BIGNUM_CUDA gcd;
    init_zero(&gcd);
    
    // Calculate GCD using extended Euclidean algorithm
    bn_extended_gcd(a, b, NULL, NULL, &gcd);
    
    // Numbers are coprime if their GCD is 1
    return bn_is_one(&gcd);
}

// Basic window size calculation
__device__ int BN_window_bits_for_exponent_size(int bits) {
    if (bits > 671) return 6;
    if (bits > 239) return 5;
    if (bits > 79)  return 4;
    if (bits > 23)  return 3;
    return 1;
}

// Check if a bit is set
__device__ bool BN_is_bit_set(const BIGNUM_CUDA *a, int n) {
    if (n < 0) return 0;
    int word_index = n / BN_ULONG_NUM_BITS;
    int bit_index = n % BN_ULONG_NUM_BITS;
    
    if (word_index >= a->top) return 0;
    return (a->d[word_index] & ((BN_ULONG)1 << bit_index)) != 0;
}

__device__ bool bn_mod_add_quick(BIGNUM_CUDA *r, const BIGNUM_CUDA *a, const BIGNUM_CUDA *b, const BIGNUM_CUDA *m) {
    // Return false if either input is negative or >= m
    if (a->neg || b->neg || bn_cmp(a, m) >= 0 || bn_cmp(b, m) >= 0) {
        return false;
    }

    // Compute t = a + b
    BIGNUM_CUDA t;
    init_zero(&t);
    absolute_add(&t, a, b);  // Use existing absolute_add function
    
    // If t < m, result is t
    // If t >= m, result is t - m
    if (bn_cmp(&t, m) >= 0) {
        absolute_subtract(r, &t, m);
    } else {
        bn_copy(r, &t);
    }

    r->neg = 0;  // Result is always non-negative
    return true;
}

__device__ bool bn_mod_sub_quick(BIGNUM_CUDA *r, const BIGNUM_CUDA *a, const BIGNUM_CUDA *b, const BIGNUM_CUDA *m) {
    // Return false if any input is negative or >= m
    if (a->neg || b->neg || bn_cmp(a, m) >= 0 || bn_cmp(b, m) >= 0) {
        return false;
    }

    // If a >= b, compute r = a - b
    // If a < b, compute r = m - (b - a)
    if (bn_cmp(a, b) >= 0) {
        absolute_subtract(r, a, b);
        r->neg = 0;
    } else {
        // First compute (b - a)
        BIGNUM_CUDA temp;
        init_zero(&temp);
        absolute_subtract(&temp, b, a);

        // Then compute m - (b - a)
        absolute_subtract(r, m, &temp);
        r->neg = 0;
    }

    return true;
}

__device__ bool bn_lshift1(BIGNUM_CUDA *r, const BIGNUM_CUDA *a) {
    // Initialize result if r is different from a
    if (r != a) {
        r->neg = a->neg;
        if (r->top < a->top + 1) {
            init_zero(r);
            r->top = a->top + 1;
        }
    } else {
        // Ensure r has enough space for potential carry
        if (r->top < a->top + 1) {
            r->top = a->top + 1;
        }
    }

    BN_ULONG carry = 0;
    for (char i = 0; i < a->top; i++) {
        BN_ULONG t = a->d[i];
        r->d[i] = ((t << 1) | carry) & BN_ULONG_MAX;
        carry = t >> (BN_ULONG_NUM_BITS - 1);
    }
    
    // Handle final carry if any
    if (carry) {
        r->d[a->top] = carry;
        r->top = a->top + 1;
    } else {
        r->top = find_top_optimized(r, a->top + 1);
    }
    return true;
}

__device__ bool bn_mod_lshift1_quick(BIGNUM_CUDA *r, const BIGNUM_CUDA *a, const BIGNUM_CUDA *m) {
    // Check preconditions
    if (a->neg || bn_cmp(a, m) >= 0) {
        printf("Error: Input must be non-negative and less than modulus\n");
        return false;
    }

    // Perform left shift by 1 bit
    if (!bn_lshift1(r, a)) {
        return false;
    }

    // Compare with modulus and subtract if necessary
    if (bn_cmp(r, m) >= 0) {
        if (!bn_sub(r, r, m)) {
            return false;
        }
    }
    return true;
}