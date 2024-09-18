// bignum.h
#include <limits.h>
#include <assert.h>
#include <stdio.h>
#include <stdint.h>

#ifndef BN_ULONG
#define BN_ULONG unsigned long long
#endif

#define BN_ULONG_MAX ((BN_ULONG)-1)

#define debug_print false
#define bn_mul_caching false
#define collect_stats false
#define BN_MASK2 0xffffffff
#define BN_ULONG_NUM_BITS (sizeof(BN_ULONG) * 8) // 64 bits
#define MAX_BIGNUM_SIZE 10     // Allow room for temp calculations
#define PUBLIC_KEY_SIZE 33  // Assuming a 33-byte public key (compressed format)

// Debug variables
#define DEVICE_CLOCK_RATE 1708500
__device__ unsigned int debug_loop_counter_bn_div = 0;  // Global loop counter variable
__device__ double elapsed_time_bn_div = 0;
__device__ double elapsed_time_bn_div_binary = 0;
__device__ double elapsed_time_bn_mod_inverse = 0;
__device__ double elapsed_time_bn_copy = 0;

// Statistics module ++
#define MAX_FUNCTIONS 100

enum FunctionIndex {
    FN_MAIN,
    FN_BN_ADD,
    FN_BN_SUB,
    FN_BN_MUL,
    FN_BN_DIV,
    FN_BN_MOD,
    FN_POINT_ADD,
    FN_POINT_DOUBLE,
    FN_EC_POINT_SCALAR_MUL,
    FN_LEFT_SHIFT,
    FN_CACHED_BN_MUL,
    FN_FIND_IN_CACHE,
    FN_COUNT
};

__device__ unsigned int g_function_calls[MAX_FUNCTIONS];
__device__ unsigned long long g_function_times[MAX_FUNCTIONS];

__device__ void record_function(FunctionIndex fn, clock_t start_time) {
    if (!collect_stats) return;
    clock_t end_time = clock64();
    atomicAdd(&g_function_calls[fn], 1);
    atomicAdd(&g_function_times[fn], end_time - start_time);
}

__device__ const char* get_function_name(FunctionIndex fn) {
    switch(fn) {
        case FN_MAIN: return "testKernel";
        case FN_BN_ADD: return "bn_add";
        case FN_BN_SUB: return "bn_sub";
        case FN_BN_MUL: return "bn_mul";
        case FN_BN_DIV: return "bn_div";
        case FN_BN_MOD: return "bn_mod";
        case FN_POINT_ADD: return "point_add";
        case FN_POINT_DOUBLE: return "point_double";
        case FN_EC_POINT_SCALAR_MUL: return "ec_point_scalar_mul";
        case FN_LEFT_SHIFT: return "left_shift";
        case FN_CACHED_BN_MUL: return "cached_bn_mul";
        case FN_FIND_IN_CACHE: return "find_in_cache";
        default: return "Unknown";
    }
}

__device__ void print_performance_report() {
    if (!collect_stats) return;
    // Print CSV header
    printf("Function,Calls,TotalTime(cycles)\n");
    
    // Print data for each function
    for (int i = 0; i < FN_COUNT; i++) {
        printf("%s,%u,%llu\n", 
               get_function_name((FunctionIndex)i), 
               g_function_calls[i], 
               g_function_times[i]);
    }
}
// Statistics module --

typedef struct bignum_st {
  BN_ULONG d[MAX_BIGNUM_SIZE];
  unsigned char top;
  bool neg;
} BIGNUM;

// Global zero-initialized BIGNUM
__device__ const BN_ULONG ZERO_ARRAY[MAX_BIGNUM_SIZE] = {0};
__device__ const BIGNUM ZERO_BIGNUM = {
    {0},                  // d (will be properly initialized in init_zero)
    1,                    // top (unsigned char)
    0                    // neg (bool)
};

// Initialize BIGNUM
__device__ void init_zero(BIGNUM *bn) {
    *bn = ZERO_BIGNUM;
}

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
            printf("%llx", a->d[i]);
        } else {
            printf("%016llx", a->d[i]);
        }
    }
    printf("\n");
}

__device__ void bn_print_constant(const char* msg, BIGNUM* a, int tid) {
    printf("Thread %d - %s", tid, msg);
    if (a->neg) {
        printf("-");  // Handle the case where BIGNUM is negative
    }
    for (int i = MAX_BIGNUM_SIZE - 1; i >= 0; i--) {
        // Print words up to top - 1 with appropriate formatting
        if (i == MAX_BIGNUM_SIZE - 1) {
            printf("%llx", a->d[i]);
        } else {
            printf("%016llx", a->d[i]);
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

__device__ bool bn_add(BIGNUM *result, BIGNUM *a, BIGNUM *b);
__device__ int bn_mod(BIGNUM *r, BIGNUM *m, BIGNUM *d);
__device__ bool bn_is_zero(BIGNUM *a);

__device__ size_t bn_strlen(const char *str) {
    size_t len = 0;
    while (*str != '\0') {
        ++len;
        ++str;
    }
    return len;
}

__device__ void bn_strcpy(char *dest, const char *src) {
    size_t i = 0;
    while (src[i] != '\0') {
        dest[i] = src[i];
        ++i;
    }
    dest[i] = '\0';
}

__device__ void print_as_hex_char(unsigned char *data, int len) {
    if (debug_print) {
        for (int i = 0; i < len; i++) {
            printf("%02x", data[i]);
        }
        printf("\n");
    }
}

__device__ void bn_print_short(const char* msg, BIGNUM* a) {
    if (!debug_print) return;
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
            printf("%016llx", a->d[i]);
        }
    }
    printf("\n");
}

__device__ void bn_print_reversed(const char* msg, BIGNUM* a) {
    if (!debug_print) return;
    printf("%s", msg);
    if (a->top == 0) {
        printf("0\n");  // Handle the case where BIGNUM is zero
        return;
    }
    if (a->neg) {
        printf("-");  // Handle the case where BIGNUM is negative
    }
    for (int i = 0; i < a->top; i++) {
        if (i == 0) {
            printf("%llx", a->d[i]);
        } else {
            printf(" %016llx", a->d[i]);
        }
    }
    printf("\n");
}

__device__ void debug_printf(const char *fmt, ...) {
    if (debug_print) {
        printf(fmt);
    }
}

__device__ BN_ULONG bn_sub_words(BN_ULONG* r, const BN_ULONG* a, const BN_ULONG* b, const int n) {
  
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

__device__ void init_one(BIGNUM *bn) {
    // Initialize the BIGNUM to zero
    *bn = ZERO_BIGNUM;
    
    // Set the least significant word to 1
    bn->d[0] = 1;
    
    // Set the top to 1 (as there is one significant digit)
    bn->top = 1;
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

__device__ int bn_cmp_one(BIGNUM* a) {
    int a_top = a->top - 1;

    // Skip leading zeroes to find the actual top for a.
    // Though theoretically, since we are comparing against 1, there shouldn't be leading zeroes. This is for safety.
    while (a_top >= 0 && a->d[a_top] == 0) a_top--;

    // a cannot be one if it's negative or if it has more than one significant digit that isn't zero
    if (a->neg || a_top != 0) { 
        return (a->neg) ? -1 : 0; // Return -1 if a is negative, indicating a is less than one;
                                  // otherwise, return 0 as an indication of inequality
    }

    // At this point, a_top should be 0 (indicating only one significant digit), and a should be positive
    // Now, directly compare a->d[0] with 1
    if (a->d[0] > 1) return 1;  // a is greater than one
    if (a->d[0] < 1) return -1; // a is less than one

    return 0; // a is equal to one
}

// Helper function to perform a deep copy of BIGNUM
__device__ void bn_copy(BIGNUM *dest, BIGNUM *src) {
    // Declare variable to store clock() value
    clock_t start, end;
    // Start the clock
    start = clock64();    

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
   
    // End the clock
    end = clock64();
    // Calculate the elapsed time
    elapsed_time_bn_copy += (double)(end - start);
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

__device__ bool bn_subtract(BIGNUM *result, BIGNUM *a, BIGNUM *b) {
    clock_t start = clock64();
    // If one is negative and the other is positive, it's essentially an addition.
    if (a->neg != b->neg) {
        result->neg = a->neg; // The sign will be the same as the sign of 'a'.
        absolute_add(result, a, b); // Perform the addition of magnitudes here because signs are different.
        record_function(FN_BN_SUB, start);
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
    record_function(FN_BN_SUB, start);
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

__device__ void bn_add_private(BIGNUM* a, BIGNUM* b, BIGNUM* r) {
    int max = a->top > b->top ? a->top : b->top;
    BN_ULONG carry = 0;
    printf("Starting addition... max: %d\n", max);

    for(int i=max-1; i>=0; i--) {
        BN_ULONG ai = (i < a->top) ? a->d[i] : 0;
        BN_ULONG bi = (i < b->top) ? b->d[i] : 0;

        BN_ULONG sum = ai + bi + carry;
        r->d[i] = sum;
        carry = (sum < ai || (sum - ai) < bi) ? 1 : 0;
    }

    // If there's a carry after processing all words
    if (carry) {
        r->top = max + 1;
        for (int i = r->top-1; i > 0; i--) {   // Shift every word to the right
            r->d[i] = r->d[i-1];
        }
        r->d[0] = carry;  // Place the carry on the leftmost side
    } else {
        r->top = max;
    }
}

__device__ bool bn_add(BIGNUM *result, BIGNUM *a, BIGNUM *b) {
    clock_t start = clock64();
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

    record_function(FN_BN_ADD, start);
    return true;
}

__device__ void big_num_add_mod(BN_ULONG *result, BN_ULONG *a, BN_ULONG *b, BN_ULONG *n, int num_words) {
    BN_ULONG carry = 0;
    for (int i = num_words - 1; i >= 0; i--) {
        BN_ULONG sum = a[i] + b[i] + carry;
        carry = (sum < a[i]) || (carry > 0 && sum == a[i]) ? 1 : 0;
        result[i] = sum;
    }

    // Modular reduction: simply subtract n from result if result >= n
    bool greater_or_equal = true;
    for (int i = 0; i < num_words; i++) {
        if (result[i] < n[i]) {
            greater_or_equal = false;
            break;
        }
        if (result[i] > n[i]) break;
    }

    if (greater_or_equal) {
        // At this point, we know result >= n, so perform result -= n
        carry = 0;
        for (int i = num_words - 1; i >= 0; i--) {
            BN_ULONG diff = result[i] - n[i] - carry;
            carry = (result[i] < n[i]) || (carry > 0 && result[i] == n[i]) ? 1 : 0;
            result[i] = diff;
        }
    }
}

__device__ void robust_BN_nnmod(BIGNUM *r, BIGNUM *m, BIGNUM *d) {
    // Copy m into r
    bn_copy(r, m);
    r->neg = 0;  // Result is non-negative

    // Now we'll reduce r modulo d, using simple division
    for (int i = 0; i < r->top; ++i) {
        if (r->d[i] >= d->d[0]) {
            BN_ULONG quotient = r->d[i] / d->d[0];
            BN_ULONG remainder = r->d[i] % d->d[0];

            // Subtract quotient*d from r
            BN_ULONG borrow = 0;
            for (int j = 0; j < d->top && i+j < r->top; ++j) {
                unsigned long long sub = (unsigned long long)r->d[i+j] + BN_ULONG_MAX + 1 - 
                                         (unsigned long long)d->d[j] * quotient - borrow;
                r->d[i+j] = (BN_ULONG)sub;
                borrow = (sub <= BN_ULONG_MAX) ? 1 : 0;
            }

            // Add back the remainder at position i
            unsigned long long sum = (unsigned long long)r->d[i] + remainder;
            r->d[i] = (BN_ULONG)sum;
            BN_ULONG carry = (sum > BN_ULONG_MAX) ? 1 : 0;

            // Propagate any carry
            for (int j = i+1; j < r->top && carry; ++j) {
                sum = (unsigned long long)r->d[j] + carry;
                r->d[j] = (BN_ULONG)sum;
                carry = (sum > BN_ULONG_MAX) ? 1 : 0;
            }

            // If there's still a carry, increase the size of r
            if (carry && r->top < MAX_BIGNUM_SIZE) {
                r->d[r->top] = carry;
                r->top++;
            }
        }
    }

    // Ensure the result is smaller than d
    while (bn_cmp(r, d) >= 0) {
        bn_subtract(r, r, d);
    }
}

// Public key derivation ++
__device__ int bn_div(BIGNUM *a, BIGNUM *b, BIGNUM *q, BIGNUM *r);
__device__ void bn_mul(BIGNUM *a, BIGNUM *b, BIGNUM *product);
// bn_mul cache ++
#define MAX_CACHE_SIZE 320

typedef struct {
    BN_ULONG key;
    BIGNUM value;
    int valid;
} CacheEntry;

typedef struct {
    CacheEntry entries[MAX_CACHE_SIZE];
} Cache;

__device__ unsigned int hash(BN_ULONG key) {
    return key % MAX_CACHE_SIZE;
}

__device__ void cache_init(Cache* cache) {
    memset(cache, 0, sizeof(Cache));
}

__device__ void cache_set(Cache* cache, BN_ULONG key, BIGNUM* value) {
    unsigned int index = hash(key);
    cache->entries[index].key = key;
    cache->entries[index].value = *value;
    cache->entries[index].valid = 1;
}

__device__ int cache_get(Cache* cache, BN_ULONG key, BIGNUM* value) {
    clock_t start = clock64();
    unsigned int index = hash(key);
    if (cache->entries[index].valid && cache->entries[index].key == key) {
        *value = cache->entries[index].value;
        record_function(FN_CACHED_BN_MUL, start);
        return 1;
    }
    record_function(FN_CACHED_BN_MUL, start);
    return 0;
}

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
        bn_subtract(&prev_x, &temp, &prev_x); // new prev_x = prev_x - temp
        bn_mul(&quotient, y, &temp); // temp = quotient*y
        bn_subtract(&last_y, &temp, &last_y); // new last_y = last_y - temp
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

__device__ void bn_mul_0(BIGNUM *a, BIGNUM *b, BIGNUM *product) {
    clock_t start = clock64();
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
    record_function(FN_BN_MUL, start);
}

__device__ void bn_mul_1(BIGNUM *a, BIGNUM *b, BIGNUM *product) {
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
__device__ void bn_mul_2(BIGNUM *a, BIGNUM *b, BIGNUM *product) {
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
    bn_subtract(&temp, &z1, &z0);
    bn_subtract(&z1, &temp, &z2);

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

    product->neg = a->neg ^ b->neg;
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

__device__ int bn_mod_mpz(BIGNUM *r, BIGNUM *m, BIGNUM *d) {    
    // Check if r and d are the same pointer
    if (r == d) {
        printf("bn_mod: ERR_R_PASSED_INVALID_ARGUMENT\n");
        return 0;
    }

    // Create a temporary BIGNUM to store the divisor
    BIGNUM temp_divisor;
    init_zero(&temp_divisor);

    // Copy the divisor to the temporary BIGNUM
    if (r == d) {
        bn_copy(&temp_divisor, d);
        d = &temp_divisor;
    }

    // Perform the division
    if (!bn_div(NULL, r, m, d)) {
        return 0;
    }

    // Adjust the sign of the remainder if necessary
    if (r->neg) {
        // If the remainder is negative, add the absolute value of the divisor
        if (d->neg) {
            if (!bn_subtract(r, r, d)) {
                return 0;
            }
        } else {
            if (!bn_add(r, r, d)) {
                return 0;
            }
        }
    }
    return 1;
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
            result = bn_subtract(&tmp, r, n); // tmp = r - n
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

__device__ int bn_is_negative(const BIGNUM *a) {
    // Assuming the neg field is defined and holds the sign (0 for non-negative, 1 for negative)
    return a->neg != 0;
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

__device__ int get_msb_bit(BIGNUM *n) {
    if (n->top == 0) return -1; // All zero

    BN_ULONG word = n->d[n->top - 1]; 
    if (word == 0) return -1; // Top word should not be zero 

    // Use __clzll to count the leading zeros in the most significant word
    unsigned int leading_zeros = __clzll(word);

    // The position of the most significant bit is the number of bits in the word
    // minus the number of leading zeros
    return (n->top - 1) * BN_ULONG_NUM_BITS + (BN_ULONG_NUM_BITS - 1 - leading_zeros);
}

__device__ void bn_init_for_shift(BIGNUM *result, BIGNUM *a, int shift) {
    // Calculate the number of words needed for the result after the shift.
    int extra_word = (get_msb_bit(a) + shift) / BN_ULONG_NUM_BITS;
    int new_top = a->top + extra_word;

    // Ensure result has enough space to hold the new value.
    // It should at least match the new_top or be the maximum allowed by MAX_BIGNUM_SIZE.
    unsigned char result_dmax = min(new_top, MAX_BIGNUM_SIZE);

    // Initialize the 'result' words to zero.
    for (int i = 0; i < result_dmax; i++) {
        result->d[i] = 0;
    }

    // Set the 'top' field for 'result'.
    result->top = 0; // Will be set correctly in bn_lshift_res
}


__device__ void bn_lshift_res(BIGNUM *result, BIGNUM *a, int shift) {
    bn_init_for_shift(result, a, shift);
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
    for (int i = result->top; i < MAX_BIGNUM_SIZE; ++i) {
        result->d[i] = 0;
    }
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

// Helper function to get the index of the MSB within a single word
__device__ int get_msb_index(BN_ULONG word) {
    // This is a simple example using a linear scan; this can be made more efficient, for example,
    // by using the built-in __clz() or similar instructions specific to your architecture.
    for (int i = BN_ULONG_NUM_BITS - 1; i >= 0; --i) {
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
            //return i * WORD_BITS + msb_index;  // Return the global index of the MSB
            return i * BN_ULONG_NUM_BITS + msb_index;  // Return the global index of the MSB
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

__device__ void bn_rshift(BIGNUM *result, BIGNUM *a, int shift) {
    // Assuming a function init_rshift_for_shift should be there similar to bn_init_for_shift.
    bn_init_for_shift(result, a, -shift);

    if (shift <= 0) {
        bn_copy(result, a);
        return;
    }

    // Initialize result BIGNUM according to your BIGNUM structure definition
    // Ensure that result->d has enough space to hold the result

    BN_ULONG carry = 0;
    int word_shift = shift / BN_ULONG_NUM_BITS;
    int bit_shift = shift % BN_ULONG_NUM_BITS;

    // Perform the bit shift for each word from the most significant downwards.
    for (int i = a->top - 1; i >= 0; --i) {
        BN_ULONG new_carry = a->d[i] << (BN_ULONG_NUM_BITS - bit_shift); // Capture the shifted-in bits
        result->d[i - word_shift] = (a->d[i] >> bit_shift) | carry; // Shift and add carry
        carry = new_carry; // Update carry for the next iteration
    }

    // Note: Negative indexing into result->d array should be handled, i.e., don't attempt to write
    // to indices less than zero. This also includes updating result->top appropriately.

    // Update top according to the number of shifted-out words
    result->top = a->top - word_shift;
    if (bit_shift > 0 && a->top > 0 && result->d[a->top - 1] == 0) {
        result->top--;
    }

    // Initialize remaining higher-order words to zero
    for (int i = result->top; i < MAX_BIGNUM_SIZE; ++i) {
        result->d[i] = 0;
    }
}

__device__ BN_ULONG bn_mul_words(BN_ULONG* result, BN_ULONG* a, BN_ULONG q, int n) {
    BN_ULONG carry = 0;
    for (int i = 0; i < n; i++) {
        // Unsigned long multiplication and addition
        // Note that we're using a 128-bit type to capture the full product
        unsigned __int128 full_product = (unsigned __int128)a[i] * (unsigned __int128)q + carry;
        carry = full_product >> BN_ULONG_NUM_BITS; // extract the higher part as carry
        result[i] = (BN_ULONG)full_product; // keep the lower part in the result
    }
    return carry; // The last carry may need to be added to the subtraction part
}

__device__ BN_ULONG bn_mul_sub_words(BIGNUM *r, BIGNUM *a, int n, BN_ULONG q) {
    // Assuming result has enough space
    BN_ULONG temp[MAX_BIGNUM_SIZE];
    // Initialize temp array to 0
    for (int i = 0; i < MAX_BIGNUM_SIZE; i++) temp[i] = 0;
    
    // First, multiply a by q, store in temp
    BN_ULONG carry = bn_mul_words(temp, a->d, q, a->top);

    // Store the carry if required
    temp[a->top] = carry;

    // Now shift temp to the left by n words
    for (int i = MAX_BIGNUM_SIZE - 1; i >= n; i--) {
        temp[i] = temp[i - n];
    }
    for (int i = 0; i < n; i++) {
        temp[i] = 0; // Fill shifted in words with 0
    }

    // Finally, subtract temp from r using bn_sub_words and return the borrow
    return bn_sub_words(r->d, r->d, temp, r->top); // Note: r->top should be adjusted considering the n shift
}

__device__ void convert_word_to_binary(BN_ULONG word, int bits[]) {
  for (int i = 0; i < BN_ULONG_NUM_BITS; ++i) {
    bits[i] = (word >> i) & 1;
  }
}

__device__ BN_ULONG convert_binary_to_word(int bits[]) {
  BN_ULONG word = 0;
  for (int i = 0; i < BN_ULONG_NUM_BITS; ++i) {
    word <<= 1;
    word |= bits[i];
  }
  return word;
}

__device__ int compare_bits(int a_bits[], int b_bits[], int n) {
  for(int i = n-1; i >= 0; --i) {
    if (a_bits[i] < b_bits[i]) {
      return -1;
    } else if (a_bits[i] > b_bits[i]) {
      return 1;
    }
  }
  return 0;
}

__device__ void subtract_bits(int a_bits[], int b_bits[], int n) {
  int borrow = 0;
  for(int i = 0; i < n; ++i) {
    a_bits[i] -= b_bits[i] + borrow;
    if (a_bits[i] < 0) {
      a_bits[i] += 2;
      borrow = 1;
    } else {
      borrow = 0;
    }
  }
}

__device__ void convert_to_binary_array(BN_ULONG value[], int binary[], int words) {
    for (int word = words - 1; word >= 0; --word) {
        for (int i = 0; i < BN_ULONG_NUM_BITS; ++i) {
            binary[(words - 1 - word) * BN_ULONG_NUM_BITS + i] = (value[word] >> (BN_ULONG_NUM_BITS - 1 - i)) & 1;
        }
    }
}

__device__ void convert_back_to_bn_ulong(int binary[], BN_ULONG value[], int words) {
    for (int word = 0; word < words; ++word) {
        value[word] = 0;
        for (int i = 0; i < BN_ULONG_NUM_BITS; ++i) {
            value[word] |= ((BN_ULONG)binary[word * BN_ULONG_NUM_BITS + (BN_ULONG_NUM_BITS - 1 - i)] << i);
        }
    }
}

__device__ void convert_back_to_bn_ulong_reversed(int binary[], BN_ULONG value[], int words) {
    for (int word = 0; word < words; ++word) {
        value[words - 1 - word] = 0;
        for (int i = 0; i < BN_ULONG_NUM_BITS; ++i) {
            value[words - 1 - word] |= ((BN_ULONG)binary[word * BN_ULONG_NUM_BITS + (BN_ULONG_NUM_BITS - 1 - i)] << i);
        }
    }
}

__device__ void binary_print_big_endian(const char* msg, int binary[], int total_bits) {
    printf("\n%s: \n", msg);
    for (int i = 0; i < total_bits; i++) {
        printf("%d", binary[i]);
        if ((i + 1) % BN_ULONG_NUM_BITS == 0) {
            printf("\n");
        }
    }
    printf("\n");
}

__device__ void reverse_chunks(int arr[], int total_bits, int chunk_size) {
    int num_chunks = total_bits / chunk_size;
    for (int i = 0; i < num_chunks / 2; ++i) {
        int start1 = i * chunk_size;
        int start2 = (num_chunks - i - 1) * chunk_size;
        // Swap the chunks
        for (int j = 0; j < chunk_size; ++j) {
            int temp = arr[start1 + j];
            arr[start1 + j] = arr[start2 + j];
            arr[start2 + j] = temp;
        }
    }
}

__device__ void bn_print_quotient(const char* msg, BIGNUM* a) {
    printf("%s", msg);
    if (a->top == 0) {
        printf("0\n");
        return;
    }
    if (a->neg) {
        printf("-");
    }
    int i = a->top - 1;
    printf("%llx", a->d[i]);
    for (i = a->top - 2; i >= 0; i--) {
        printf("%016llx", a->d[i]);
    }
    printf("\n");
}

__device__ int binary_compare(const int *binary1, const int *binary2, int num_bits) {
    for (int i = num_bits - 1; i >= 0; --i) {
        if (binary1[i] > binary2[i]) {
            // binary1 is greater than binary2
            return 1;
        } else if (binary1[i] < binary2[i]) {
            // binary1 is less than binary2
            return -1;
        }
        // If binary1[i] equals binary2[i], continue checking the next bit
    }
    // binary1 and binary2 are equal
    return 0;
}

// Helper function to determine the 'top' field value for a BIGNUM from a binary array
__device__ int get_bn_top_from_binary_array(const int binary[], int total_bits) {
    for (int i = total_bits - 1; i >= 0; --i) {
        if (binary[i]) {
            return (i / BN_ULONG_NUM_BITS) + 1;
        }
    }
    return 1; // If every bit is zero, top is one
}

__device__ int get_bn_top_from_binary_array_little_endian(const int binary[], int total_bits) {
    int last_non_zero_index = -1; // This will store the last index where binary[i] is non-zero
    for (int i = 0; i < total_bits; ++i) {
        if (binary[i]) {
            last_non_zero_index = i;
        }
    }
    if (last_non_zero_index == -1) {
        return 1; // If every bit is zero, top is one
    } else {
        return (last_non_zero_index / BN_ULONG_NUM_BITS) + 1;
    }
}

__device__ void bn_div_binary(
    int dividend[],
    int divisor[],
    int quotient[],
    int remainder[],
    int dividend_words,
    int divisor_words
) {
    // Declare variable to store clock() value
    clock_t start, end;
    // Start the clock
    start = clock64();

    const int total_bits = MAX_BIGNUM_SIZE * BN_ULONG_NUM_BITS;
    int temp[total_bits];
    memset(temp, 0, sizeof(temp));

    for (int i = 0; i < total_bits; ++i) {
        // Shift temp left by 1
        for (int j = 0; j < total_bits - 1; ++j) {
            temp[j] = temp[j+1];
        }
        temp[total_bits - 1] = dividend[i];

        // Check if temp is greater than or equal to divisor
        int can_subtract = 1;
        for (int j = 0; j < total_bits; ++j) {
            if (temp[j] != divisor[j]) {
                can_subtract = temp[j] > divisor[j];
                break;
            }
        }
        // Subtract divisor from temp if temp >= divisor
        if(can_subtract) {
            quotient[i] = 1;
            for (int j = total_bits - 1; j >= 0; --j) {
                temp[j] -= divisor[j];
                if (temp[j] < 0) {  // Borrow from the next bit if needed
                    temp[j] += 2;
                    temp[j-1] -= 1;
                }
            }
        } else {
            quotient[i] = 0;
        }
    }

    // Remainder is in temp after division
    memcpy(remainder, temp, total_bits * sizeof(int));

    // End the clock
    end = clock64();
    // Calculate the elapsed time
    elapsed_time_bn_div_binary += (double)(end - start);
}

__device__ void left_shift(BIGNUM *a, int shift) {
    clock_t start = clock64();
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

    record_function(FN_LEFT_SHIFT, start);
}

// Function to search for a B value in the cache
__device__ int find_in_cache(BN_ULONG B, BN_ULONG B_values[], int cache_count) {
    // init start timer
    // We may know the place of B in the cache. TODO: Implement a better search algorithm
    clock_t start = clock64();
    for (int i = 0; i < cache_count; i++) {
        if (B_values[i] == B) {
            record_function(FN_FIND_IN_CACHE, start);
            return i;
        }
    }
    record_function(FN_FIND_IN_CACHE, start);
    return -1;
}

__device__ int bn_div(BIGNUM *bn_quotient, BIGNUM *bn_remainder, BIGNUM *bn_dividend, BIGNUM *bn_divisor)
{
    clock_t start = clock64();

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
        record_function(FN_BN_DIV, start);
        return 1;
    }
    // Perform long division
    BIGNUM current_dividend;
    init_zero(&current_dividend);
    char dividend_size = abs_dividend.top;

    #if bn_mul_caching
        // Initialize cache arrays
        BN_ULONG B_values[MAX_CACHE_SIZE];
        BIGNUM products[MAX_CACHE_SIZE];
        int cache_count = 0;
    #endif

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

            // 
            #if bn_mul_caching
                int cache_index = find_in_cache(mid, B_values, cache_count);
                if (cache_index != -1) {
                    product = products[cache_index];
                } else {
                    bn_mul(&abs_divisor, &temp, &product);
                    if (cache_count < MAX_CACHE_SIZE) {
                        B_values[cache_count] = mid;
                        products[cache_count] = product;
                        cache_count++;
                    }
                    else {
                        printf("[0] Cache miss. %016llx is more than %d\n", mid, MAX_CACHE_SIZE);
                    }
                }
            #else
                bn_mul(&abs_divisor, &temp, &product);
            #endif

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

        #if bn_mul_caching
            int cache_index = find_in_cache(q, B_values, cache_count); // Shell runtime: 362.258584028 seconds
            if (cache_index != -1) {
                product = products[cache_index];
            } else {
                bn_mul(&abs_divisor, &temp, &product);
                if (cache_count < MAX_CACHE_SIZE) {
                    B_values[cache_count] = q;
                    products[cache_count] = product;
                    cache_count++;
                }
                else {
                    printf("[1] Cache miss. %016llx is more than %d\n", q, MAX_CACHE_SIZE);
                }
            }
        #else
            bn_mul(&abs_divisor, &temp, &product);
        #endif

        bn_subtract(&current_dividend, &current_dividend, &product);
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

    record_function(FN_BN_DIV, start);
    return 1;
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
    result->neg = 0;
}

__device__ void bn_set_signed_word(BIGNUM *r, int64_t value) {
    // Clear any existing value in r.
    // Assuming MAX_BIGNUM_SIZE is defined and represents the maximum size of d[].
    for (int i = 0; i < MAX_BIGNUM_SIZE; ++i) {
        r->d[i] = 0;
    }

    // Set the sign in r. Assuming the sign is represented by a simple integer where
    // negative numbers have sign = -1 and non-negatives have sign = 0.
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
    BN_ULONG temp_d[MAX_BIGNUM_SIZE];
    for (int i = 0; i < MAX_BIGNUM_SIZE; i++) {
        temp_d[i] = a->d[i];
    }
    //a->d = b->d;
    for (int i = 0; i < MAX_BIGNUM_SIZE; i++) {
        a->d[i] = b->d[i];
    }
    //b->d = temp_d;
    for (int i = 0; i < MAX_BIGNUM_SIZE; i++) {
        b->d[i] = temp_d[i];
    }
    
    // Swap the scalar components such as top, sign etc.
    int temp_top = a->top;
    a->top = b->top;
    b->top = temp_top;

    int temp_sign = a->neg;
    a->neg = b-> neg;
    b->neg = temp_sign;
}

__device__ int is_even(const BIGNUM* num) {
    // Considering that the least significant part of the number
    // is stored at the start of the array.
    // And assuming that your BIGNUM structure uses an array of integers
    // to represent the number, named `d` for the data.
    
    // Check the least significant bit of the least significant part.
    // num->d[0] represents the least significant part of the BIGNUM.
    // If the LSB is 0, it means the number is even.
    if (num->d[0] & 1) {
        return 0; // Odd number
    } else {
        return 1; // Even number
    }
}

__device__ void bn_gcd(BIGNUM* r, BIGNUM* in_a, BIGNUM* in_b) {
    printf("++ bn_gcd ++\n");
    bn_print(">> in_a: ", in_a);
    bn_print(">> in_b: ", in_b);
    BIGNUM a, b, temp;
    int shifts = 0;

    // Initialize BIGNUM variables
    init_zero(&a);
    init_zero(&b);
    init_zero(&temp);

    // Copy in_a and in_b to a and b respectively because we need to modify them
    bn_copy(&a, in_a);
    bn_copy(&b, in_b);

    // Check if a and b are equal
    if (bn_cmp(&a, &b) == 0) {
        bn_copy(r, &a); // Set the result to a (or b, since they are equal)
        return; // Exit the function early
    }

    // Check if either a or b is zero at the start and set r accordingly
    if (bn_is_zero(&a)) {
        // Since a is zero, GCD(a, b) = b by definition
        bn_copy(r, &b);
        return; // Exit the function early
    }
    if (bn_is_zero(&b)) {
        // Since b is zero, GCD(a, b) = a by definition
        bn_copy(r, &a);
        return; // Exit the function early
    }

    // Step 1: remove common factors of 2 from a and b
    while (is_even(&a) && is_even(&b)) {
        bn_rshift_one(&a); // equivalent to a /= 2;
        bn_rshift_one(&b); // equivalent to b /= 2;
        shifts++;
    }

    // Make sure a is odd
    while (is_even(&a)) {
        bn_rshift_one(&a);
    }

    do {
        // Remove factors of 2 from b, as b will eventually become the GCD
        while (is_even(&b)) {
            bn_rshift_one(&b);
        }

        // Swap if necessary to ensure that a <= b
        if (bn_cmp(&a, &b) > 0) {
            // Swap a and b
            bn_swap(&a, &b);
        }

        bn_subtract(&b, &b, &a); // b = b - a
    } while (!bn_is_zero(&b));

    // Step 3: adjust the result to include the factors of 2 we removed earlier
    BIGNUM temp_a;
    init_zero(&temp_a);
    bn_lshift_res(&temp_a, &a, shifts); // equivalent to a *= 2^shifts;

    // Copy the result to r
    bn_copy(r, &temp_a);

    bn_print("<< bn_gcd r: ", r);
    printf("-- bn_gcd --\n");
}

__device__ void swap_bignum_pointers(BIGNUM** a, BIGNUM** b) {
    BIGNUM* temp = *a;
    *a = *b;
    *b = temp;
}

__device__ void bn_gcdext(BIGNUM *g, BIGNUM *s, BIGNUM *t, BIGNUM *a, BIGNUM *b) {
    printf("\n++ bn_gcdext ++\n");
    printf("\n");
    BIGNUM old_s, old_t, old_r, r, quotient, temp;
    init_zero(&old_s);
    init_zero(&old_t);
    init_zero(&old_r);
    init_zero(&r);
    init_zero(&quotient);
    init_zero(&temp);

    bn_copy(&old_r, b);
    bn_copy(&r, a);
    bn_set_word(&old_s, 0);
    bn_set_word(s, 1);
    bn_set_word(&old_t, 1);
    bn_set_word(t, 0);

    while (!bn_is_zero(&r)) {
        bn_div(&quotient, &temp, &old_r, &r);
        bn_copy(&old_r, &r);
        bn_copy(&r, &temp);
        bn_mul(&temp, &quotient, s);
        bn_subtract(&temp, &old_s, &temp);
        bn_copy(&old_s, s);
        bn_copy(s, &temp);
        bn_mul(&temp, &quotient, t);
        bn_subtract(&temp, &old_t, &temp);
        bn_copy(&old_t, t);
        bn_copy(t, &temp);
    }

    // Use bn_gcd to calculate the GCD
    bn_gcd(g, a, b);
    
    // Adjust the signs of s and t based on the input values
    if (bn_is_negative(a)) {
        old_s.neg = !old_s.neg;
    }
    if (bn_is_negative(b)) {
        old_t.neg = !old_t.neg;
    }

    bn_copy(s, &old_s);
    bn_copy(t, &old_t);

    bn_print("\n<< g: ", g);
    bn_print("<< s: ", s);
    bn_print("<< t: ", t);
    printf("-- bn_gcdext --\n");
}

__device__ bool bn_mod_inverse(BIGNUM *result, BIGNUM *a, BIGNUM *n) {
    clock_t start, end;
    // Start the clock
    start = clock64();
    bool debug = 0;
    if (bn_is_one(n)) {
        return false;  // No modular inverse exists
    }

    BIGNUM r;
    BIGNUM nr;
    BIGNUM t;
    BIGNUM nt;
    BIGNUM q;
    BIGNUM tmp;
    BIGNUM tmp2;
    BIGNUM tmp3;

    init_zero(&r);
    init_zero(&nr);
    init_zero(&t);
    init_one(&nt);
    init_zero(&q);
    init_zero(&tmp);
    init_zero(&tmp2);
    init_zero(&tmp3);

    bn_copy(&r, n);
    bn_mod(&nr, a, n); // Compute non-negative remainder of 'a' modulo 'n'
    unsigned int counter = 0;
    while (!bn_is_zero(&nr)) {
        bn_div(&q, &tmp, &r, &nr); // Compute quotient and remainder
        bn_copy(&tmp, &nt);
        bn_mul(&q, &nt, &tmp2); // tmp2 = q * nt
        init_zero(&tmp3);
        bn_subtract(&tmp3, &t, &tmp2); // tmp3 = t - tmp2
        bn_copy(&nt, &tmp3); // dst << src
        bn_copy(&t, &tmp);
        bn_copy(&tmp, &nr);
        bn_mul(&q, &nr, &tmp2);
        init_zero(&tmp3);
        bn_subtract(&tmp3, &r, &tmp2); // tmp3 = r - tmp2
        bn_copy(&nr, &tmp3);
        bn_copy(&r, &tmp);
        if (debug) counter++;
    }

    if (!bn_is_one(&r)) {
        init_zero(result);
        delete &r;
        delete &nr;
        delete &t;
        delete &nt;
        delete &q;
        delete &tmp;
        delete &tmp2;
        return false; // No modular inverse exists
    }

    if (bn_is_negative(&t)) {
        bn_add(&tmp2, &t, n); // tmp2 = t + n
        bn_copy(&t, &tmp2);
    }

    bn_copy(result, &t);

    delete &r;
    delete &nr;
    delete &t;
    delete &nt;
    delete &q;
    delete &tmp;
    delete &tmp2;
    // Stop the clock
    end = clock64();
    elapsed_time_bn_mod_inverse += (double)(end - start);
    return true;
}

__device__ void bn_to_hex_str(BIGNUM *bn, char *str) {
    int i, j, v;
    char hex_chars[] = "0123456789ABCDEF";
    j = 0;

    for (i = bn->top - 1; i >= 0; i--) {
        for (int shift = BN_ULONG_NUM_BITS - 4; shift >= 0; shift -= 4) {
            v = (bn->d[i] >> shift) & 0xf;
            if (v || j > 0 || i == 0) {
                str[j++] = hex_chars[v];
            }
        }
    }
    str[j] = '\0';
}

__device__ size_t dev_strlen(const char *str) {
    size_t len = 0;
    while (str[len] != '\0') {
        len++;
    }
    return len;
}

__device__ void bignum_to_bit_array(BIGNUM *n, unsigned int *bits) {
    int index = 0;
    
    // Iterate through the words in reverse order
    for (int i = 0; i < n->top; ++i) {
        BN_ULONG word = n->d[i];
        // For each word, iterate through bits from most significant to least significant
        for (int j = 0; j < BN_ULONG_NUM_BITS; ++j) {
            bits[index++] = (word >> j) & 1;
        }
    }

    // If n->top < 4, fill the remaining bits with zeros
    while (index < 256) {
        bits[index++] = 0;
    }
}

__device__ void reverse_order(BIGNUM *test_values_a, const unsigned char words_count) {
    for (size_t j = 0; j < words_count / 2; j++) {
        BN_ULONG temp_a = test_values_a->d[j];
        test_values_a->d[j] = test_values_a->d[words_count - 1 - j];
        test_values_a->d[words_count - 1 - j] = temp_a;
    }
}

__device__ void bufferToHex(const uint8_t *buffer, char *output) {
    // Init output
    for (size_t i = 0; i < PUBLIC_KEY_SIZE * 2 + 1; i++) {
        output[i] = '\0';
        if (i > 66) {
            printf("Error: bufferToHex output buffer overflow\n");
        }
    }
    const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < PUBLIC_KEY_SIZE; i++) {
        output[i * 2] = hex_chars[buffer[i] >> 4];
        output[i * 2 + 1] = hex_chars[buffer[i] & 0xF];
    }
    output[PUBLIC_KEY_SIZE * 2] = '\0';
}