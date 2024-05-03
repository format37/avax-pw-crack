// bignum.h
// Set the OPENSSL_API_COMPAT preprocessor macro to a compatible value.
// Adjust the value of OPENSSL_API_COMPAT based on the OpenSSL version 
// you are using and the compatibility level required by your code. 
// #define OPENSSL_API_COMPAT 10101000L 

#include "bn.h"
#include <assert.h>
#define debug_print false
#define BN_MASK2 0xffffffff;
#define BN_ULONG_NUM_BITS 64
//#define MAX_BIGNUM_WORDS 4     // For 256-bit numbers
#define MAX_BIGNUM_WORDS 9     // For 576-bit numbers
#define MAX_BIGNUM_SIZE 9     // Allow room for temp calculations


typedef struct bignum_st {
  BN_ULONG d[MAX_BIGNUM_SIZE];
  int top;
  int dmax;
  int neg;
  int flags;
} BIGNUM;

__device__ bool bn_add(BIGNUM *result, BIGNUM *a, BIGNUM *b);
__device__ int bn_mod(BIGNUM *r, BIGNUM *m, BIGNUM *d);
__device__ bool bn_is_zero(BIGNUM *a);

__device__ void bn_print(const char* msg, BIGNUM* a) {
    printf("%s", msg);
    // if (a->top == 0) {
    //     printf("0\n");  // Handle the case where BIGNUM is zero
    //     return;
    // }
    if (a->neg) {
        printf("-");  // Handle the case where BIGNUM is negative
    }
    // int size_of_d = sizeof(a->d);
    for (int i = MAX_BIGNUM_SIZE - 1; i >= 0; i--) {
        // Print words up to top - 1 with appropriate formatting
        if (i == MAX_BIGNUM_SIZE - 1) {
            printf("%llx", a->d[i]);
        } else {
            //printf(" %016llx", a->d[i]);
            printf("%016llx", a->d[i]);
        }
    }
    printf("\n");
}

__device__ void bn_print_short(const char* msg, BIGNUM* a) {
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
            //printf(" %016llx", a->d[i]); // TODO: Enable this line
            printf("%016llx", a->d[i]);
        }
    }
    printf("\n");
}

__device__ void bn_print_reversed(const char* msg, BIGNUM* a) {
    printf("%s", msg);
    if (a->top == 0) {
        printf("0\n");  // Handle the case where BIGNUM is zero
        return;
    }
    if (a->neg) {
        printf("-");  // Handle the case where BIGNUM is negative
    }
    for (int i = 0; i < a->top; i++) {
    //for (int i = 0; i < MAX_BIGNUM_WORDS; i++) {
        // Print words up to top - 1 with appropriate formatting
        if (i == 0) {
            printf("%llx", a->d[i]);
        } else {
            printf(" %016llx", a->d[i]);
        }
    }
    printf("\n");
}

__device__ int find_top(BIGNUM *bn, int max_words) {
    // bn_print("++ find_top bn ++ ", bn);
    // int size_of_d = sizeof(bn->d);
    // int safe_size = min(size_of_d, max_words);
    for (int i = MAX_BIGNUM_SIZE - 1; i >= 0; i--) {
        // printf(">> find_top. size_of_d: %d i: %d bn->d[i]: %llx max_words: %d\n", size_of_d, i, bn->d[i], max_words);
        if (bn->d[i] != 0) {
            return i + 1;  // The top index is the index of the last non-zero word plus one
        }
    }
    return 1; // If all words are zero, the top is 0
}

__device__ void free_bignum(BIGNUM *bn) {
    delete[] bn->d;
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
    // int size_of_d = sizeof(bn->d);
    // printf("++ init_zero ++ Allocating %d words. sizeof(bn->d): %d\n", capacity, size_of_d);
    //bn->d = new BN_ULONG[capacity]; // Dynamically allocate the required number of words.
    // BN_ULONG bn_d[MAX_BIGNUM_SIZE] = {0};
    // bn->d = bn_d;
    
    for (int i = 0; i < MAX_BIGNUM_SIZE; i++) {
        // printf(">> init_zero. set up bn->d[%d]", i);
        // printf(" from %llx to 0\n", bn->d[i]);
        bn->d[i] = 0;
    }

    // top is used for representing the actual size of the 
    // significant part of the number for calculation purposes.
    bn->top = 1; // There are no significant digits when all words are zero.

    bn->neg = 0;
    
    // dmax is used to manage the memory allocation and ensure you 
    // do not access out-of-bounds memory.
    // bn->dmax = capacity; // Make sure to track the capacity in dmax.
    bn->dmax = MAX_BIGNUM_SIZE - 1;
    // delete[] bn_d;
}

__device__ void init_one(BIGNUM *bn, int capacity) {
    init_zero(bn, capacity); // Initialize the BIGNUM to zero first
    for (int i = 1; i < capacity; i++) {
        bn->d[i] = 0;
    }
    bn->d[0] = 1;           // Set the least significant word to 1
    // bn->top = (capacity > 0) ? 1 : 0; // There is one significant digit if capacity allows
    bn->top = 1;
    bn->neg = 0;             // The number is non-negative
    //bn->dmax = capacity;     // Track the capacity in dmax
    bn->dmax = MAX_BIGNUM_SIZE;
}

__device__ int bn_cmp(BIGNUM* a, BIGNUM* b) {
    // printf("++ bn_cmp ++\n");
    // bn_print(">> a: ", a);
    // printf(">> a.top: %d\n", a->top);
    // printf(">> a.dmax: %d\n", a->dmax);
    // printf(">> a.neg: %d\n", a->neg);
    // bn_print(">> b: ", b);
    // printf(">> b.top: %d\n", b->top);
    // printf(">> b.dmax: %d\n", b->dmax);
    // printf(">> b.neg: %d\n", b->neg);

    // print a.d[4]
    // printf("a.d[4]: %llx\n", a->d[3]);
    // print b.d[4]
    // printf("b.d[4]: %llx\n", b->d[3]);
    // bn_print("[0] bn_cmp a: ", a);
    // bn_cmp logic:
    //  1 when a is larger
    // -1 when b is larger
    //  0 wneh a and b are equal

  // Skip leading zeroes and find the actual top for a
  // int a_top = a->top - 1;
  // while (a_top >= 0 && a->d[a_top] == 0) a_top--;
  int a_top = find_top(a, MAX_BIGNUM_WORDS);
  //   printf("2>> a.top: %d\n", a->top);

  // Skip leading zeroes and find the actual top for b
  // int b_top = b->top - 1;
  // while (b_top >= 0 && b->d[b_top] == 0) b_top--;
  int b_top = find_top(b, MAX_BIGNUM_WORDS);
  // printf("2>> b.top: %d\n", b->top);

  // Compare signs
  if (a->neg && !b->neg) {return -1;} // a is negative, b is positive: a < b
  if (!a->neg && b->neg) {return 1;}  // a is positive, b is negative: a > b
  // bn_print("[1] bn_cmp a: ", a);

  // If both numbers are negative, we need to reverse the comparison of their magnitudes
  int sign_factor = (a->neg && b->neg) ? -1 : 1;
  // bn_print("[2] bn_cmp a: ", a);
  // Now, use the actual tops for comparison
  if (a_top > b_top) {return sign_factor * 1;} // Consider sign for magnitude comparison
  // bn_print("[3] bn_cmp a: ", a);
  if (a_top < b_top) {return sign_factor * -1;}
  // bn_div(("[4] bn_cmp a: ", a);
    
  // Both numbers have the same number of significant digits, so compare them starting from the most significant digit
  for (int i = a_top-1; i >= 0; i--) {
    if (a->d[i] > b->d[i]) {return sign_factor * 1;} // a is larger (or smaller if both are negative)
    
    if (a->d[i] < b->d[i]) { // b is larger (or smaller if both are negative)
        // printf("[5].%d a->d[i]: %llx is  less than b->d[i]: %llx\n", i, a->d[i], b->d[i]);
        return sign_factor * -1;
        } 
  }
    //   printf("Numbers are equal\n");
    //   printf("-- bn_cmp --\n");
  return 0; // Numbers are equal
}

__device__ int bn_cmp_abs(BIGNUM *a, BIGNUM *b) {
    // Check tops // TODO: This may need optimization. Top is often incorrect in point_add
    // if (find_top(a, MAX_BIGNUM_SIZE) != a->top) {
    //     printf("### bn_cmp_abs ### Error: Top is not set correctly in the source BIGNUM.\n");
    //     printf("a->top: %d, actual top: %d\n", a->top, find_top(a, MAX_BIGNUM_WORDS));
    //     // Print bn value
    //     bn_print("a: ", a);
    // }
    // if (find_top(b, MAX_BIGNUM_SIZE) != b->top) {
    //     printf("### bn_cmp_abs ### Error: Top is not set correctly in the source BIGNUM.\n");
    //     printf("b->top: %d, actual top: %d\n", b->top, find_top(b, MAX_BIGNUM_WORDS));
    //     // Print bn value
    //     bn_print("b: ", b);
    // }
    // Set tops
    //a->top = find_top(a, MAX_BIGNUM_SIZE); // This stuck in a loop
    //b->top = find_top(b, MAX_BIGNUM_SIZE);

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

/*__device__ int bn_cmp_v0(BIGNUM* a, BIGNUM* b) {
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
}*/

// Helper function to perform a deep copy of BIGNUM
__device__ void bn_copy(BIGNUM *dest, BIGNUM *src) {
    /*printf("++ bn_copy ++\n");
    bn_print(">> src: ", src);
    bn_print(">> dest: ", dest);*/

    // Init dst as zero
    init_zero(dest, MAX_BIGNUM_SIZE);
    // int size = sizeof(src->d);
    // init_zero(dest, size);

    if (dest == nullptr || src == nullptr) {
        return;
    }

    src->top = find_top(src, MAX_BIGNUM_SIZE);
    //printf("# src.top: %d\n", src->top);

    // Copy the neg and top fields
    dest->neg = src->neg;
    dest->top = src->top;

    // Copy the array of BN_ULONG digits.
    for (int i = 0; i < src->top; i++) {
        dest->d[i] = src->d[i];
    }

    // Set the rest of the words in dest to 0 if dest's top is larger
    for (int i = src->top; i < MAX_BIGNUM_SIZE; i++) {
        dest->d[i] = 0;
    }

    // Check dst top
    int top = find_top(dest, MAX_BIGNUM_SIZE);
    dest->top = top;

    dest->dmax = src->dmax;
    
    // bn_print("<< src: ", src);
    // bn_print("<< dest: ", dest);
    // printf("-- bn_copy --\n");
}

__device__ void bn_copy_0(BIGNUM *dest, BIGNUM *src) {
    printf("++ bn_copy ++\n");
    bn_print(">> src: ", src);
    bn_print(">> dest: ", dest);

    // Init dst as zero
    init_zero(dest, MAX_BIGNUM_SIZE);
    // Set dst top to 1
    dest->top = 1;
    // Set dst neg to 0
    dest->neg = 0;

    if (dest == nullptr || src == nullptr) {
        //printf("### bn_copy ### Error: Destination or source BIGNUM is null.\n");
        return;
    }

    // Check src top
    int top = find_top(src, MAX_BIGNUM_SIZE);
    if (top != src->top) {
        //printf("### bn_copy ### Error: SRC Top is not set correctly in the source BIGNUM.\n");
        //printf("src->top: %d, actual top: %d\n", src->top, top);
        src->top = top;
        // Print bn value
        // bn_print("src: ", src);
    }

    //bn_print("[1] src: ", src);
    //bn_print("[1] dest: ", dest);

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
    // Check dst top
    top = find_top(dest, MAX_BIGNUM_SIZE);
    if (top != dest->top) {
        //printf("### bn_copy ### Error: DST Top is not set correctly in the destination BIGNUM.\n");
        //printf("dest->top: %d, actual top: %d\n", dest->top, top);
        dest->top = top;
        // Print bn value
        //bn_print("dest: ", dest);
    }
    //bn_print("[2] src: ", src);
    //bn_print("[2] dest: ", dest);
    dest->dmax = src->dmax;
    
    bn_print("<< src: ", src);
    bn_print("<< dest: ", dest);
    printf("-- bn_copy --\n");
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
        if (result->top < MAX_BIGNUM_SIZE - 1) {
            result->d[result->top] = carry; // Assign carry to the new word
            result->top++;
        } else {
            // Handle error: Result BIGNUM doesn't have space for an additional word.
            // This should potentially be reported back to the caller.
        }
    }

    // Find the real top after addition (no leading zeroes)
    result->top = find_top(result, MAX_BIGNUM_SIZE);
}

__device__ void absolute_subtract(BIGNUM *result, BIGNUM *a, BIGNUM *b) {
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

__device__ bool bn_subtract(BIGNUM *result, BIGNUM *a, BIGNUM *b) {
    //printf("bn_subtract:\n");
    // Check tops # TODO: This may need optimization. Top is often incorrect in point_add
    // if (find_top(a, MAX_BIGNUM_SIZE) != a->top) {
    //     printf("### bn_cmp_abs ### Error: Top is not set correctly in the source BIGNUM.\n");
    //     printf("a->top: %d, actual top: %d\n", a->top, find_top(a, MAX_BIGNUM_SIZE));
    // }
    // if (find_top(b, MAX_BIGNUM_SIZE) != b->top) {
    //     printf("### bn_cmp_abs ### Error: Top is not set correctly in the source BIGNUM.\n");
    //     printf("b->top: %d, actual top: %d\n", b->top, find_top(b, MAX_BIGNUM_SIZE));
    // }
    // set tops
    // a->top = find_top(a, MAX_BIGNUM_SIZE); // This stuck in a loop
    // b->top = find_top(b, MAX_BIGNUM_SIZE);
    //bn_print("a: ", a);
    //bn_print("b: ", b);

    // If one is negative and the other is positive, it's essentially an addition.
    if (a->neg != b->neg) {
        result->neg = a->neg; // The sign will be the same as the sign of 'a'.
        absolute_add(result, a, b); // Perform the addition of magnitudes here because signs are different.
        // bn_print("result: ", result);
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

    // Update result.top based on the actual data in result.
    result->top = find_top(result, MAX_BIGNUM_SIZE);

    // Perform additional logic if underflow has been detected in absolute_subtract.
    if (result->top == 0) { 
        // Handle underflow if needed. 
    }
    //bn_print("result: ", result);
    return true;
}

__device__ void bn_add_v0(BIGNUM *result, BIGNUM *a, BIGNUM *b) {
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
    // #define BN_ULONG_NUM_BITS 64
    // #define MAX_BIGNUM_WORDS 4     // For 256-bit numbers
    // #define MAX_BIGNUM_SIZE 8     // Allow room for temp calculations

    // typedef struct bignum_st {
    // BN_ULONG *d;
    // int top;
    // int dmax;
    // int neg;
    // int flags;
    // } BIGNUM;
    /*printf("++ bn_add ++\n");
    bn_print(">> a: ", a);
    printf(">> a.top: %d\n", a->top);
    printf(">> a.dmax: %d\n", a->dmax);
    printf(">> a.neg: %d\n", a->neg);
    printf(">> a.flags: %d\n", a->flags);
    bn_print(">> b: ", b);
    printf(">> b.top: %d\n", b->top);
    printf(">> b.dmax: %d\n", b->dmax);
    printf(">> b.neg: %d\n", b->neg);
    printf(">> b.flags: %d\n", b->flags);
    bn_print(">> result: ", result);
    printf(">> result.top: %d\n", result->top);
    printf(">> result.dmax: %d\n", result->dmax);
    printf(">> result.neg: %d\n", result->neg);
    printf(">> result.flags: %d\n", result->flags);*/
    // Clear the result first.
    result->top = 0;
    for (int i = 0; i < MAX_BIGNUM_WORDS; i++) {
        result->d[i] = 0;
    }

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

    // Lastly, normalize the result to remove any leading zeros that could have appeared.
    find_top(result, MAX_BIGNUM_WORDS);
    // bn_print("<< result: ", result);
    // printf("-- bn_add --\n");
    return true;
}

__device__ void bn_mod_deprecated(BIGNUM* r, BIGNUM* m, BIGNUM* d) {
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
                res += (1LL << BN_ULONG_NUM_BITS); // Assuming each BN_ULONG is 32 bits
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

__device__ int bn_nnmod_deprecated(BIGNUM *r, BIGNUM *m, BIGNUM *d)
{
    printf("++ BN_nnmod ++\n");
    bn_print(">> r: ", r);
    bn_print(">> m: ", m);
    bn_print(">> d: ", d);
    // Check for division by zero
    if (d->top == 0) {
        return 0; // Error code
    }

    // Check if r and d are the same pointer
    if (r == d) {
        printf("BN_nnmod: ERR_R_PASSED_INVALID_ARGUMENT\n");
        return 0;
    }

    // Perform the modulo operation using BN_mod
    if (!bn_mod(r, m, d)) {
        printf("BN_mod failed\n");
        return 0; // Error code
    }
    bn_print("[1] r: ", r);
    bn_print("[1] m: ", m);
    bn_print("[1] d: ", d);

    // Check the sign of the result
    if (!r->neg) {
        printf("r is not negative\n");
        return 1;
    }

    BIGNUM tmp;
    init_zero(&tmp, MAX_BIGNUM_WORDS);
    if (d->neg) {
        printf("d is negative\n");
        if (!bn_subtract(&tmp, r, d)) { // tmp = r - d
            printf("BN_sub failed\n");
            return 0;
        }
    } else {
        printf("d is not negative\n");
        if (!bn_add(r, r, d)) {
            printf("BN_add failed\n");
            return 0;
        }
    }

    printf("returning 1\n");
    return 1; // Success
}

__device__ int simple_BN_nnmod_deprecated(BIGNUM *r, const BIGNUM *m, const BIGNUM *d)
{
    printf("ATTENTION: simple_BN_nnmod can operates only with single word!\n");
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
        carry = (BN_ULONG) (sum >> BN_ULONG_NUM_BITS); // Upper 32 bits become carry
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
                borrow = (BN_ULONG) (sub >> BN_ULONG_NUM_BITS);
            }

            // Add back the remainder at position i
            unsigned long long sum = (unsigned long long) r->d[i] + (unsigned long long) remainder;
            r->d[i] = (BN_ULONG) (sum % 0x100000000);
            BN_ULONG carry = (BN_ULONG) (sum >> BN_ULONG_NUM_BITS);

            // Propagate any carry
            for (int j = i+1; j < r->top && carry; ++j) {
                sum = (unsigned long long) r->d[j] + carry;
                r->d[j] = (BN_ULONG) (sum % 0x100000000);
                carry = (BN_ULONG) (sum >> BN_ULONG_NUM_BITS);
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

__device__ int bn_div(BIGNUM *a, BIGNUM *b, BIGNUM *q, BIGNUM *r);
__device__ void bn_mul(BIGNUM *a, BIGNUM *b, BIGNUM *product);
__device__ bool bn_sub(BIGNUM *a, BIGNUM *b, BIGNUM *r);


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
    
    
    //return P->x.top == 0; // Assuming a valid x coordinate can never have top == 0, except for the point at infinity
    if (bn_is_zero(&P->x) || bn_is_zero(&P->y)) {
        return 1; // P is the point at infinity
    }
    return 0; // P is not the point at infinity


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
    // BN_ULONG zero_d[MAX_BIGNUM_SIZE] = {0}; // Assuming BN_ULONG is the type used to represent a single "word" of the BIGNUM.

    // zero.d = zero_d;
    // // zero.top = (zero_d[0] != 0); // If we've set zero_d[0] to 0, zero's top should be zero, implying an actual value of 0.
    // zero.top = 0;
    // zero.dmax = 1; // The maximum number of "words" in the BIGNUM. Since zero is just 0, this is 1.
    init_zero(&zero, MAX_BIGNUM_WORDS);

    //BIGNUM *temp_remainder = new BIGNUM(); // If dynamic memory is allowed - or statically allocate enough space if not
    BIGNUM temp_remainder;

    while (bn_cmp(&remainder, &zero) != 0) {
        // bn_div(&last_remainder, &remainder, &quotient);
        bn_div(&last_remainder, &remainder, &quotient, &temp_remainder); // Now using 4 arguments
        BIGNUM swap_temp = last_remainder; // Temporary storage for the swap
        // last_remainder = *temp_remainder;
        // *temp_remainder = swap_temp;
        bn_copy(&last_remainder, &temp_remainder);
        bn_copy(&temp_remainder, &swap_temp);

        bn_mul(&quotient, x, &temp); // temp = quotient*x
        bn_sub(&prev_x, &temp, &prev_x); // new prev_x = prev_x - temp
        bn_mul(&quotient, y, &temp); // temp = quotient*y
        bn_sub(&last_y, &temp, &last_y); // new last_y = last_y - temp
        
        // Swap last_remainder with remainder
        // Swap prev_x with x
        // Swap last_y with y
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

__device__ bool bn_sub(BIGNUM *r, BIGNUM *a, BIGNUM *b) {
    printf("ATTENTION: bn_sub is deprecated. Use bn_subtract instead.\n");
    // TODO: Implement check that r, a and b are different pointers
    //printf("++ bn_sub ++\n");
    // get top of a and b
    a->top = find_top(a, MAX_BIGNUM_WORDS);
    b->top = find_top(b, MAX_BIGNUM_WORDS);

    //bn_print(">> a: ", a);
    //bn_print(">> b: ", b);

    int max = a->top > b->top ? a->top : b->top;
    BN_ULONG borrow = 0;
    //printf("max: %d\n", max);
    
    for (int i = 0; i < max; ++i) {
        //debug_printf("# 4.%d\n", i);
        BN_ULONG ai = (i < a->top) ? a->d[i] : 0;
        BN_ULONG bi = (i < b->top) ? b->d[i] : 0;

        // Check if a subtraction would cause a borrow
        if (ai >= bi + borrow) {
            /*debug_printf("# 5\n");
            debug_printf("r->top: %d\n", r->top);
            debug_printf("i: %d\n", i);
            debug_printf("r->d[i]: %llu\n", r->d[i]);
            debug_printf("ai: %llu\n", ai);
            debug_printf("bi: %llu\n", bi);
            debug_printf("borrow: %llu\n", borrow);            */
            r->d[i] = ai - bi - borrow;
            //debug_printf("# 6\n");
            borrow = 0;
        } else {
            // Borrow from the next highest bit
            r->d[i] = (1ULL << (sizeof(BN_ULONG) * 8)) + ai - bi - borrow;
            borrow = 1;
        }
    }
    //debug_printf("# 8\n");
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
    
    //r->neg = 0; // Assuming we don't want negative numbers, otherwise set sign properly
    // Define the neg flag based on the signs of a and b and the result of the subtraction
    if (a->neg && !b->neg) {
        // 'a' is negative, 'b' is positive
        r->neg = 1;
    } else if (!a->neg && b->neg) {
        // 'a' is positive, 'b' is negative
        r->neg = 0;
    } else {
        // Both numbers have the same sign
        int cmp = bn_cmp(a, b);
        if (cmp < 0) {
            // |a| < |b|
            r->neg = !a->neg; // Result has the opposite sign of 'a'
        } else if (cmp > 0) {
            // |a| > |b|
            r->neg = a->neg; // Result has the same sign as 'a'
        } else {
            // |a| == |b|
            r->neg = 0; // Result is zero, so it's positive
        }
    }
    bn_print("<< r: ", r);
    // print r.neg
    printf("r->neg: %d\n", r->neg);
    return true;
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

__device__ void bn_add_bignum_words(BIGNUM *r, BIGNUM *a, int n) {
    BN_ULONG carry = 0;
    // Ensure that the 'a' BIGNUM is shifted left by 'n' words before adding
    for (int i = 0; i < r->top; i++) {
        unsigned long long sum = (unsigned long long) r->d[i] + (i - n >= 0 ? a->d[i - n] : 0) + carry;
        r->d[i] = (BN_ULONG)(sum & 0xFFFFFFFFFFFFFFFFULL); // Keep the lower bits
        carry = sum >> BN_ULONG_NUM_BITS; // Propagate the carry
    }

    // If there is still carry left after the last word processed,
    // propagate it further. This assumes that r has space for at least r->top + 1 words
    if (carry) {
        if (r->top < r->dmax) { // Check if there is space for the carry
            r->d[r->top] += carry; // Add the carry
        }
        // If r->d[r->top] overflows, we need to handle additional carry which could lead to incrementing r->top
        // ... additional code may be required here to handle that case properly
    }
}

__device__ void bn_mul(BIGNUM *a, BIGNUM *b, BIGNUM *product) {
    // printf("++ bn_mul ++\n");
    // bn_print(">> a: ", a);
    // bn_print(">> b: ", b);
    // Reset the product
    for(int i = 0; i < a->top + b->top; i++)
        product->d[i] = 0;
    
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
    //bn_print("<< a: ", a);
    //bn_print("<< b: ", b);
    // bn_print("<< product: ", product);
    // printf("-- bn_mul --\n");
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

__device__ int bn_mod_mpz(BIGNUM *r, BIGNUM *m, BIGNUM *d) {
    // printf("++ bn_mod ++\n");
    
    // Check if r and d are the same pointer
    if (r == d) {
        printf("bn_mod: ERR_R_PASSED_INVALID_ARGUMENT\n");
        return 0;
    }

    // Create a temporary BIGNUM to store the divisor
    BIGNUM temp_divisor;
    init_zero(&temp_divisor, MAX_BIGNUM_WORDS);

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

    // printf("-- bn_mod --\n");
    return 1;
}

__device__ int bn_mod(BIGNUM *r, BIGNUM *a, BIGNUM *n) {
    bool debug = 0;
    if (debug) {
        printf("++ bn_mod ++\n");
        bn_print(">> r: ", r);
        bn_print(">> a(m): ", a);
        printf(">> a.top: %d\n", a->top);
        printf(">> a.neg: %d\n", a->neg);
        printf(">> a.dmax: %d\n", a->dmax);
        printf(">> a.flags: %d\n", a->flags);
        bn_print(">> n(d): ", n);
        printf(">> n.top: %d\n", n->top);
        printf(">> n.neg: %d\n", n->neg);
        printf(">> n.dmax: %d\n", n->dmax);
        printf(">> n.flags: %d\n", n->flags);
        // print 8 words of n
        printf(">> n[8]: ");
        for (int i = 0; i < 8; i++) {
            printf(" %016llx", n->d[i]);
        }
        printf("\n");
    }
    BIGNUM q;
    init_zero(&q, MAX_BIGNUM_SIZE);

    if (r == n) {
        printf("bn_mod: ERR_R_PASSED_INVALID_ARGUMENT");
        return 0;
    }

    // bn_print(">> a before bn_div: ", a);
    // bn_print(">> n before bn_div: ", n);
    if (!bn_div(&q, r, a, n)) {
        // bn_print("<<0 q after bn_div: ", &q);
        // bn_print("<<0 r after bn_div: ", r);
        return 0;
    }
    // bn_print("<<1 q after bn_div: ", &q);
    // bn_print("<<1 r after bn_div: ", r);

    BIGNUM tmp;
    init_zero(&tmp, MAX_BIGNUM_SIZE);

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

__device__ int bn_mod_v0(BIGNUM *r, BIGNUM *a, BIGNUM *n) {
    printf("++ bn_mod ++\n");
    // int BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx)
    BIGNUM q;
    init_zero(&q, MAX_BIGNUM_WORDS);

    /*
     * like BN_mod, but returns non-negative remainder (i.e., 0 <= r < |d|
     * always holds)
     */
    /*if (r == n) {
        printf("bn_mod_for_div: ERR_R_PASSED_INVALID_ARGUMENT")
        return 0;
    }*/

    /*
    - `dv` (quotient) is where the result of the division is stored.
    - `rem` (remainder) is where the remainder of the division is stored.
    - `m` is the dividend.
    - `d` is the divisor.
    - `ctx` is the context used for memory management during the operation in original OpenSSL implementation.
    */
    // return bn_divide_rev2(&q, r, a, n); // quotient, remainder, 
    printf("-- bn_mod --> bn_div..\n");
    return bn_div(&q, r, a, n); // quotient, remainder, 
}

__device__ void mod_mul(BIGNUM *a, BIGNUM *b, BIGNUM *mod, BIGNUM *result) {
    debug_printf("mod_mul 0\n");
    // Product array to store the intermediate multiplication result
    // BN_ULONG product_d[MAX_BIGNUM_SIZE] ={0}; // All elements initialized to 0
    // Ensure that 'product' uses this pre-allocated array
    // BIGNUM product = { product_d, 0, MAX_BIGNUM_SIZE };
    BIGNUM product;
    init_zero(&product, MAX_BIGNUM_SIZE);
    debug_printf("mod_mul 1\n");
    // Now, you can call the bn_mul function and pass 'product' to it
    bn_mul(a, b, &product);
    debug_printf("mod_mul 2\n");
    
    
    bn_mod(&product, mod, result); // TODO: fix it


    debug_printf("mod_mul 3\n");

    // Wipe the product memory if necessary
    // for (int i = 0; i < MAX_BIGNUM_SIZE; ++i) {
    //     product_d[i] = 0;
    // }
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
    // printf("++ bn_is_zero ++\n");
    // bn_print(">>[3] bn_div divisor: ", a);
    // bn_print(">> a: ", a);
    // printf("a->top: %d\n", a->top);
    // Check a top

    int top = find_top(a, MAX_BIGNUM_SIZE);
    if (top != a->top) {
        // printf("WARNING: bn_is_zero: top is not correct\n");
        //printf("a->top: %d, actual top: %d\n", a->top, top);
        // Set the top to the correct value
        a->top = top;
    }
    for (int i = 0; i < a->top; ++i) {
        // printf(">> a->d[%d]: %llu\n", i, a->d[i]);
        if (a->d[i] != 0) {
            // printf(">> return: False\n");
            // printf("-- bn_is_zero --\n");
            return false;
        }
    }
    // printf(">> return: True\n");
    // printf("-- bn_is_zero --\n");
    return true;
}

__device__ bool bn_is_one(BIGNUM *a) {
    /*printf("++ bn_is_one ++\n");
    bn_print(">> a: ", a);*/
    // Assuming that BIGNUM stores the number in an array 'd' of integers
    // and 'top' indicates the number of chunks being used.
    // We also assume that 'd' is big-endian and 'top' is the index of the highest non-zero digit.
    
    // The number one would be represented with only the least significant digit being one
    // and all other digits being zero.
    if (a->top != 1) {  // If there are more than one digits in use, it cannot be one
        /*printf(">> return: False\n");
        printf("-- bn_is_one --\n");*/
        return false;
    }
    if (a->d[0] != 1) {  // The number one should only have the least significant digit set to one
        /*printf(">> return: False\n");
        printf("-- bn_is_one --\n");*/
        return false;
    }
    // Ensure that any other digits (if they exist in memory) are zero
    // This isn't strictly necessary if the 'top' index is always accurate
    // but is a good sanity check if there's any possibility of memory corruption or improper initialization.
    for (int i = 1; i < MAX_BIGNUM_WORDS; ++i) {
        if (a->d[i] != 0) {
            /*printf(">> return: False\n");
            printf("-- bn_is_one --\n");*/
            return false;
        }
    }
    /*printf(">> return: True\n");
    printf("-- bn_is_one --\n");*/
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
    // dest->x.d = new BN_ULONG[MAX_BIGNUM_WORDS];
    // dest->y.d = new BN_ULONG[MAX_BIGNUM_WORDS];
    // dest->x.top = 0;
    // dest->y.top = 0;
    // dest->x.neg = 0;
    // dest->y.neg = 0;
    // dest->x.dmax = MAX_BIGNUM_WORDS;
    // dest->y.dmax = MAX_BIGNUM_WORDS;
    init_zero(&dest->x, MAX_BIGNUM_WORDS);
    init_zero(&dest->y, MAX_BIGNUM_WORDS);

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
    // It should at least match the new_top or be the maximum allowed by MAX_BIGNUM_WORDS.
    result->dmax = min(new_top, MAX_BIGNUM_WORDS);

    // Initialize the 'result' words to zero.
    for (int i = 0; i < result->dmax; i++) {
        result->d[i] = 0;
    }

    // Set the 'top' field for 'result'.
    result->top = 0; // Will be set correctly in bn_lshift_res
}


__device__ void bn_lshift_res(BIGNUM *result, BIGNUM *a, int shift) {
    bn_init_for_shift(result, a, shift);
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

__device__ void bn_lshift_one(BIGNUM *bn) {
    if (bn_is_zero(bn)) {
        return; // If the big number is zero, there's nothing to shift
    }

    BN_ULONG carry = 0;
    for (int i = 0; i < bn->top; ++i) {
        // Take the current digit and the previous carry to create a composite
        BN_ULONG composite = (carry >> (BN_ULONG_NUM_BITS - 1)) | (bn->d[i] << 1);
        carry = bn->d[i] & (1 << (BN_ULONG_NUM_BITS - 1)); // Save the MSB before shifting as the next carry
        bn->d[i] = composite;
    }

    // If the most significant digit is now zero, update the `top` counter
    if (carry != 0) {
        bn->top++;
    }
}

// Helper function to get the index of the MSB within a single word
__device__ int get_msb_index(BN_ULONG word) {
    // This is a simple example using a linear scan; this can be made more efficient, for example,
    // by using the built-in __clz() or similar instructions specific to your architecture.
    //for (int i = WORD_BITS - 1; i >= 0; --i) {
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

__device__ BN_ULONG bn_div_2_words(BN_ULONG high, BN_ULONG low, BN_ULONG divisor) {

  BN_ULONG quotient = 0;
  BN_ULONG remainder = 0;
  
  // Left shift high word to upper part 
  remainder = (high << BN_ULONG_NUM_BITS); 

  // Or in low word to lower part
  remainder |= low;

  BN_ULONG divisor_shifted;

  for (int i = 0; i < BN_ULONG_NUM_BITS; ++i) {

    // Shift divisor left to align with remainder 
    divisor_shifted = divisor << i;
    
    // Check if divisor <= remainder
    if (remainder >= divisor_shifted) {

      // Subtract divisor and set quotient bit
      remainder -= divisor_shifted;  
      quotient |= (1UL << i);

    }

  }

  return quotient;

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
    for (int i = result->top; i < result->dmax; ++i) {
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

__device__ void shift_left(int bits[], int num_bits) {

    int carry = 0;

    for(int i = 0; i < num_bits; ++i) {
        
        int prev = bits[i];
        
        bits[i] <<= 1;
        bits[i] |= carry;

        carry = (prev >> (BN_ULONG_NUM_BITS - 1)) & 1;

    }

}

/*__device__ void convert_to_binary_array(BN_ULONG value[], int binary[], int words) {
    for (int word = 0; word < words; ++word) {
        for (int i = 0; i < BN_ULONG_NUM_BITS; ++i) {
            binary[word * BN_ULONG_NUM_BITS + i] = (value[word] >> (BN_ULONG_NUM_BITS - 1 - i)) & 1;
        }
    }
}*/

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
            // value[words-word-1] |= ((BN_ULONG)binary[word * BN_ULONG_NUM_BITS + (BN_ULONG_NUM_BITS - 1 - i)] << i);
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

__device__ void shift_left_v1(const int *input, int *output, int num_bits, int shift_amount) {
    // Initialize the output array to zero
    memset(output, 0, sizeof(int) * num_bits);

    // Handle cases where full words are shifted
    int full_words_shift = shift_amount / BN_ULONG_NUM_BITS;
    int bit_shift = shift_amount % BN_ULONG_NUM_BITS;

    // Shift by full words first
    for (int word = full_words_shift; word < num_bits / BN_ULONG_NUM_BITS; ++word) {
        output[word] = input[word - full_words_shift];
    }

    // Now handle the bit shifting within each word if there is any
    if (bit_shift != 0) {
        int carry = 0;
        for (int word = num_bits / BN_ULONG_NUM_BITS - 1; word >= 0; --word) {
            int new_carry = (output[word] >> (BN_ULONG_NUM_BITS - bit_shift)) & ((1U << bit_shift) - 1);
            output[word] <<= bit_shift;
            output[word] |= carry;
            carry = new_carry;
        }
    }
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

__device__ void shift_right_v1(const int *input, int *output, int num_bits, int shift_amount) {
    // Clear the output array, as we'll be setting it explicitly
    memset(output, 0, sizeof(int) * num_bits);

    // Handle cases where full words are shifted
    int full_words_shift = shift_amount / BN_ULONG_NUM_BITS;
    int bit_shift = shift_amount % BN_ULONG_NUM_BITS;

    // Shift by full words first
    for (int word = 0; word < num_bits / BN_ULONG_NUM_BITS - full_words_shift; ++word) {
        output[word] = input[word + full_words_shift];
    }

    // Now handle the bit shifting within each word if there is any
    if (bit_shift != 0) {
        int carry = 0;
        for (int word = 0; word < num_bits / BN_ULONG_NUM_BITS; ++word) {
            int new_carry = (output[word] & ((1U << bit_shift) - 1)) << (BN_ULONG_NUM_BITS - bit_shift);
            output[word] >>= bit_shift;
            output[word] |= carry;
            carry = new_carry;
        }
    }
}

__device__ void subtract_v1(const int *binary1, const int *binary2, int *output, int num_bits) {
    int borrow = 0;

    // Perform subtraction for each bit, starting from the LSB (Least Significant Bit)
    for (int i = 0; i < num_bits; ++i) {
        // Subtract the current bits plus any borrow from previous computations
        int diff = binary1[i] - binary2[i] - borrow;

        if (diff >= 0) {
            output[i] = diff;
            borrow = 0; // no borrow if the difference is non-negative
        } else {
            output[i] = diff + 2; // since it's binary, add 2 (base) to get the correct result
            borrow = 1; // we have a borrow since `diff` was negative
        }
    }
    
    // In a binary subtraction either there is no borrow at the end or the output is less than 0 
    // which cannot happen in this context, so we don't need to return the borrow or consider it after the loop.
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
    /*printf("\n++ bn_div_binary :)++\n");
    printf("dividend bits: [%d]\n", dividend_words);
    for (int i = 0; i < dividend_words; i ++) {
        for (int j = 0; j < BN_ULONG_NUM_BITS; j++) {
            printf("%d", dividend[i * BN_ULONG_NUM_BITS + j]);
        }
        printf("\n");
    }
    printf("divisor bits: [%d]\n", divisor_words);
    for (int i = 0; i < divisor_words; i ++) {
        for (int j = 0; j < BN_ULONG_NUM_BITS; j++) {
            printf("%d", divisor[i * BN_ULONG_NUM_BITS + j]);
        }
        printf("\n");
    }*/

    const int total_bits = MAX_BIGNUM_SIZE * BN_ULONG_NUM_BITS;
    int temp[total_bits];
    memset(temp, 0, sizeof(temp));

    for (int i = 0; i < total_bits; ++i) {
        // Shift temp left by 1
        for (int j = 0; j < total_bits - 1; ++j) {
            temp[j] = temp[j+1];
        }
        temp[total_bits - 1] = dividend[i];

        /*printf("Iteration %d:\n", i);
        printf("temp: ");
        for (int j = 0; j < total_bits; ++j) {
            printf("%d", temp[j]);
        }
        printf("\n");

        printf("divisor: ");
        for (int j = 0; j < total_bits; ++j) {
            printf("%d", divisor[j]);
        }
        printf("\n");*/

        // Check if temp is greater than or equal to divisor
        int can_subtract = 1;
        for (int j = 0; j < total_bits; ++j) {
            if (temp[j] != divisor[j]) {
                can_subtract = temp[j] > divisor[j];
                break;
            }
        }
        /*for (int j = total_bits - 1; j >= 0; --j) {
            if (temp[j] != divisor[j]) {
                can_subtract = temp[j] > divisor[j];
                break;
            }
        }*/
        //printf("can_subtract: %d\n", can_subtract);
        // Subtract divisor from temp if temp >= divisor
        if(can_subtract) {
            //printf(">> Subtracting is available\n");
            quotient[i] = 1;
            // quotient[total_bits - 1 - i] = 1;
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
}

__device__ int bn_div(BIGNUM *quotient_in, BIGNUM *remainder_in, BIGNUM *dividend_in, BIGNUM *divisor_in) {
    /*
    - `dv` (quotient) is where the result of the division is stored.
    - `rem` (remainder) is where the remainder of the division is stored.
    - `m` is the dividend.
    - `d` is the divisor.
    - `ctx` is the context used for memory management during the operation in original OpenSSL implementation.
    */

    // dividend
    // -------- = quotient, remainder
    // divisor
    //printf("\n++ bn_div ++\n");
    bool debug = 0;

    // Declare local BIGNUM variables
    BIGNUM quotient;
    BIGNUM remainder;
    BIGNUM dividend;
    BIGNUM divisor;
    //printf("# [0] #\n");
    // Initialize the BIGNUMs
    init_zero(&quotient, MAX_BIGNUM_SIZE);
    init_zero(&remainder, MAX_BIGNUM_SIZE);
    init_zero(&dividend, MAX_BIGNUM_SIZE);
    init_zero(&divisor, MAX_BIGNUM_SIZE);
    if (debug) {
        printf("# [1] #\n");
        bn_print(">> dividend_in: ", dividend_in);
        bn_print(">> divisor_in: ", divisor_in);
    };
    // Copy from input BIGNUMs
    bn_copy(&quotient, quotient_in);
    bn_copy(&remainder, remainder_in);
    bn_copy(&dividend, dividend_in);
    bn_copy(&divisor, divisor_in);
    //printf("# [2] #\n");
    // print input values
    /*bn_print(">> dividend: ", &dividend);
    bn_print(">> divisor: ", &divisor);*/

    // init zero to quotient and remainder
    init_zero(&quotient, MAX_BIGNUM_SIZE);
    init_zero(&remainder, MAX_BIGNUM_SIZE);
    quotient.neg = 0;
    remainder.neg = 0;
    
    // Error checks similar to OpenSSL
    //bn_print(">>[1] bn_div divisor: ", &divisor);
    if (bn_is_zero(&divisor)) {
        // Handle division by zero or similar error
        // Free the allocated memory when done
        /*free(quotient);
        free(remainder);
        free(dividend);
        free(divisor);*/
        //printf("-- bn_div -- Error: Division by zero. Divisor is zero\n");
        return 0;
    }
    if (&divisor == NULL) {
        // Handle invalid divisor
        // Free the allocated memory when done
        /*free(quotient);
        free(remainder);
        free(dividend);
        free(divisor);*/
        //printf("-- bn_div -- Error: Invalid divisor\n");
        return 0;
    }
    if (&dividend == NULL) {
        // Handle invalid dividend
        // Free the allocated memory when done
        /*free(quotient);
        free(remainder);
        free(dividend);
        free(divisor);*/
        //printf("-- bn_div -- Error: Invalid dividend\n");
        return 0;
    }

    

    const int total_bits = MAX_BIGNUM_SIZE * BN_ULONG_NUM_BITS;
    // const int total_bits = MAX_BIGNUM_SIZE * BN_ULONG_NUM_BITS;
    // printf("# total_bits: %d\n", total_bits);
    
    // Define arrays with the maximum size based on MAX_BIGNUM_WORDS
    int binary_dividend[total_bits] = {0};
    int binary_divisor[total_bits] = {0};
    int binary_quotient[total_bits] = {0};
    int binary_remainder[total_bits] = {0};
    
    // Initialize binary arrays
    memset(binary_quotient, 0, total_bits * sizeof(int));
    memset(binary_remainder, 0, total_bits * sizeof(int));

    if (debug) {
        bn_print(">> convert_to_binary_array dividend: ", &dividend);
        bn_print(">> convert_to_binary_array divisor: ", &divisor);
    };
    
    // Convert the BIGNUMs to binary arrays, use actual 'top' value for correct size
    convert_to_binary_array(dividend.d, binary_dividend, MAX_BIGNUM_SIZE);
    convert_to_binary_array(divisor.d, binary_divisor, MAX_BIGNUM_SIZE);

    //binary_print_big_endian(">> binary_dividend", binary_dividend, total_bits);
    //binary_print_big_endian(">> binary_divisor", binary_divisor, total_bits);

    // Call the binary division function
    // bn_div_binary(binary_dividend, binary_divisor, binary_quotient, binary_remainder);
    // Call the binary division function with the actual number of bits used
    bn_div_binary(
        binary_dividend, 
        binary_divisor, 
        binary_quotient, 
        binary_remainder, 
        dividend.top, 
        divisor.top
        );

    if (debug) {
        bn_print_quotient("<< binary_quotient", &quotient);
        binary_print_big_endian("<< binary_quotient", binary_quotient, total_bits);
        binary_print_big_endian("<< binary_remainder", binary_remainder, total_bits);
    };

    // Fix the 'top' fields of quotient and remainder
    quotient.top = get_bn_top_from_binary_array(binary_quotient, total_bits);
    //quotient->top = get_bn_top_from_binary_array_little_endian(binary_quotient, total_bits);
    //printf("\n# Total bits: %d\n", total_bits);
    // printf("\n# binary quotient top: %d\n", quotient.top);
    remainder.top = get_bn_top_from_binary_array(binary_remainder, total_bits);
    // printf("\n# binary remainder top: %d\n", remainder.top);

    // Convert the binary arrays back to BIGNUMs
    quotient.top = MAX_BIGNUM_SIZE;
    convert_back_to_bn_ulong(binary_quotient, quotient.d, quotient.top);
    remainder.top = MAX_BIGNUM_SIZE;
    convert_back_to_bn_ulong_reversed(binary_remainder, remainder.d, remainder.top);
    // Reverse words in the quotient
    for (int i = 0; i < quotient.top / 2; i++) {
        BN_ULONG temp = quotient.d[i];
        quotient.d[i] = quotient.d[quotient.top - i - 1];
        quotient.d[quotient.top - i - 1] = temp;
    }
    // Reverse words in the remainder
    /*for (int i = 0; i < remainder->top / 2; i++) {
        BN_ULONG temp = remainder->d[i];
        remainder->d[i] = remainder->d[remainder->top - i - 1];
        remainder->d[remainder->top - i - 1] = temp;
    }*/
    // Determine sign of quotient and remainder
    quotient.neg = dividend.neg ^ divisor.neg;
    remainder.neg = dividend.neg;

    if (debug) {
        bn_print("\n<< quotient: ", &quotient); // CHECK
        //printf("# bignum quotient top: %d\n", quotient->top);
        bn_print("<< remainder: ", &remainder);
        //printf("# bignum remainder top: %d\n", remainder->top);
    };

    // Update tops using find_top
    //quotient->top = find_top(quotient, MAX_BIGNUM_WORDS);
    //remainder->top = find_top(remainder, MAX_BIGNUM_WORDS);

    // print output values
    /*bn_print("<< bn_div quotient: ", &quotient);
    bn_print("<< bn_div remainder: ", &remainder);*/
    
    // Set the output values
    bn_copy(quotient_in, &quotient);
    bn_copy(remainder_in, &remainder);
    // Free the allocated memory when done
    /*free(quotient);
    free(remainder);
    free(dividend);
    free(divisor);*/
    //printf("-- bn_div --\n");
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
    // BN_ULONG *temp_d = a->d;
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
    
    // ... Repeat for other scalar elements of BIGNUM as necessary
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
    init_zero(&a, MAX_BIGNUM_WORDS);
    init_zero(&b, MAX_BIGNUM_WORDS);
    init_zero(&temp, MAX_BIGNUM_WORDS);

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
    
    //bn_print(">>GCD: ", &a);
    //printf(">>Shifts: %d\n", shifts);

    // Step 3: adjust the result to include the factors of 2 we removed earlier
    BIGNUM temp_a;
    init_zero(&temp_a, MAX_BIGNUM_WORDS);
    bn_lshift_res(&temp_a, &a, shifts); // equivalent to a *= 2^shifts;

    //bn_print("<<GCD: ", &temp_a);

    // Copy the result to r
    bn_copy(r, &temp_a);

    bn_print("<< bn_gcd r: ", r);
    printf("-- bn_gcd --\n");
}
/*
__device__ int bn_num_bits(BIGNUM *a) {
    if(a->top == 0) 
        return 0;

    int bitlen = (a->top - 1) * BN_ULONG_NUM_BITS;
    BN_ULONG l = a->d[a->top-1];
    int i;
    
    // Find position of highest bit set
    for (i = BN_ULONG_NUM_BITS - 1; i >= 0; i--) {
        if (((l >> i) & ((BN_ULONG)1)) != 0)
            break;
    }

    bitlen += i + 1;

    return bitlen;
}

__device__ int bn_gcd(BIGNUM *r, BIGNUM *a, BIGNUM *b) {

    int max_words = max(a->top, b->top) + 1;

    BIGNUM *g = (BIGNUM*) malloc(sizeof(BIGNUM));
    init_zero(g, max_words);

    BIGNUM *temp = (BIGNUM*) malloc(sizeof(BIGNUM));
    init_zero(temp, max_words);
    
    if (bn_is_zero(b)) {
        bn_copy(r, a);
        r->neg = 0;
        return 1;
    }
    
    if (bn_is_zero(a)) {
        bn_copy(r, b); 
        r->neg = 0;
        return 1;
    }

    // Make r and g odd by left shifting if necessary
    if (g->d[0] % 2 == 0) {
        bn_lshift_one(g); 
    }
    
    if (r->d[0] % 2 == 0) {
        bn_lshift_one(r);
    }

    // Find common powers of 2 between a and b    
    int shifts = 0;
    BN_ULONG mask;
    
    for (int i = 0; i < min(a->top, b->top); ++i) {
        mask = ~(a->d[i] | b->d[i]); 
        for (int j = 0; j < BN_ULONG_NUM_BITS; ++j) {
            if ((mask & 1) == 0) {
               ++shifts; 
            }
            mask >>= 1;
        }
    }
    
    // Remove common powers of 2
    if (shifts > 0) {
        bn_rshift(r, r, shifts);
        bn_rshift(g, g, shifts);
    }

    // Ensure working space
    int top = max(a->top, b->top) + 1;
    if (bn_wexpand(r, top) == 0 || bn_wexpand(g, top) == 0 || bn_wexpand(temp, top) == 0) {
        return 0;
    }

    // Ensure r is odd
    if (r->d[0] % 2 == 0) {
        bn_swap(g, r);
    }

    // Number of iterations
    int max_bits = max(bn_num_bits(r), bn_num_bits(g));
    int num_iters = 4 + 3 * max_bits;

    int delta = 1;
        
    for (int i = 0; i < num_iters; ++i) {

        // Conditionally flip signs
        int cond = (delta < 0) & (g->d[0] & 1); 
        delta = (-cond & -delta) | ((cond - 1) & delta);
        r->neg ^= cond;

        // Swap
        if (cond) {
            bn_swap(g, r);
        }
        
        // Elimination step
        delta++;        
        bn_add(temp, g, r);
        if (g->d[0] & 1) { 
           bn_swap(g, temp);
        }
        bn_rshift_one(g);
    }
    
    // Finalize
    r->neg = 0;
    bn_lshift_res(r, r, shifts); 
    bn_rshift_one(r);

    // Cleanup
    free(g);
    free(temp);
    
    return 1;
}
*/

__device__ void bn_gcdext_deprecated(BIGNUM *g, BIGNUM *s, BIGNUM *t, BIGNUM *a, BIGNUM *b_original) {
    printf("++ bn_gcdext_deprecated ++\n");

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
    // printf("## bn_gcdext ##\n");
    init_one(&prev_t, MAX_BIGNUM_WORDS);  // prev_t = 1
    
    // Initialize g and b for the gcd calculation
    bn_copy(g, a);
    //bn_copy(b, b);

    while (!bn_is_zero(&b_temp)) {
        bn_div(&quotient, &temp, g, &b_temp);
        
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
    printf(" -- bn_gcdext_deprecated --\n");
}

__device__ void swap_bignum_pointers(BIGNUM** a, BIGNUM** b) {
    BIGNUM* temp = *a;
    *a = *b;
    *b = temp;
}

// TODO: Debug or remove the function below
/*__device__ void bn_mod_exp(BIGNUM *r, BIGNUM *a, BIGNUM *p, BIGNUM *m) {
    int i, j, bits, ret = 0, wstart, wend, window;
    int start = 1;
    BIGNUM *d, *val[TABLE_SIZE];
    BIGNUM temp;
    init_zero(&temp, MAX_BIGNUM_WORDS);

    bits = p->top * BN_ULONG_NUM_BITS;
    if (bits == 0) {
        // x**0 mod 1, or x**0 mod -1 is still zero.
        if (bn_is_one(m) || bn_is_zero(m)) {
            init_zero(r, MAX_BIGNUM_WORDS);
        } else {
            init_one(r, MAX_BIGNUM_WORDS);
        }
        return;
    }

    for (i = 0; i < TABLE_SIZE; i++) {
        val[i] = &temp;
        init_zero(val[i], MAX_BIGNUM_WORDS);
    }

    if (!bn_mod(&temp, a, m, NULL))
        goto err;               // 1
    if (bn_is_zero(&temp)) {
        init_zero(r, MAX_BIGNUM_WORDS);
        return;
    }

    window = BN_window_bits_for_exponent_size(bits);
    if (window > 1) {
        if (!bn_mod_mul(&temp, &temp, &temp, m, NULL))
            goto err;           // 2
        j = 1 << (window - 1);
        for (i = 1; i < j; i++) {
            if (!bn_mod_mul(val[i], val[i - 1], &temp, m, NULL))
                goto err;
        }
    }

    start = 1;                  // This is used to avoid multiplication etc
                                // when there is only the value '1' in the
                                // buffer.
    wstart = bits - 1;          // The top bit of the window
    wend = 0;                   // The bottom bit of the window

    if (!bn_mod(&temp, BN_value_one(), m, NULL))
        goto err;

    for (;;) {
        int wvalue;             // The 'value' of the window

        if (bn_is_bit_set(p, wstart) == 0) {
            if (!start)
                if (!bn_mod_mul(r, r, r, m, NULL))
                    goto err;
            if (wstart == 0)
                break;
            wstart--;
            continue;
        }
        
         // We now have wstart on a 'set' bit, we now need to work out how bit
         // a window to do.  To do this we need to scan forward until the last
         // set bit before the end of the window
        wvalue = 1;
        wend = 0;
        for (i = 1; i < window; i++) {
            if (wstart - i < 0)
                break;
            if (bn_is_bit_set(p, wstart - i)) {
                wvalue <<= (i - wend);
                wvalue |= 1;
                wend = i;
            }
        }

        // wend is the size of the current window
        j = wend + 1;
        // add the 'bytes above'
        if (!start)
            for (i = 0; i < j; i++) {
                if (!bn_mod_mul(r, r, r, m, NULL))
                    goto err;
            }

        // wvalue will be an odd number < 2^window
        if (!bn_mod_mul(r, r, val[wvalue >> 1], m, NULL))
            goto err;

        // move the 'window' down further
        wstart -= wend + 1;
        start = 0;
        if (wstart < 0)
            break;
    }
    return;

err:
    return;
}*/

__device__ void bn_gcdext(BIGNUM *g, BIGNUM *s, BIGNUM *t, BIGNUM *a, BIGNUM *b) {
    printf("\n++ bn_gcdext ++\n");
    bn_print(">> a: ", a);
    bn_print(">> b: ", b);
    printf("\n");
    BIGNUM old_s, old_t, old_r, r, quotient, temp;
    init_zero(&old_s, MAX_BIGNUM_WORDS);
    init_zero(&old_t, MAX_BIGNUM_WORDS);
    init_zero(&old_r, MAX_BIGNUM_WORDS);
    init_zero(&r, MAX_BIGNUM_WORDS);
    init_zero(&quotient, MAX_BIGNUM_WORDS);
    init_zero(&temp, MAX_BIGNUM_WORDS);

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
        bn_sub(&temp, &old_s, &temp);
        bn_copy(&old_s, s);
        bn_copy(s, &temp);
        bn_mul(&temp, &quotient, t);
        bn_sub(&temp, &old_t, &temp);
        bn_copy(&old_t, t);
        bn_copy(t, &temp);
    }

    // Use bn_gcd to calculate the GCD
    bn_gcd(g, a, b);
    
    // Adjust the signs of s and t based on the input values
    if (bn_is_negative(a)) {
        // bn_negate(&old_s);
        old_s.neg = !old_s.neg;
    }
    if (bn_is_negative(b)) {
        // bn_negate(&old_t);
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
    bool debug = 0;
    if (debug) {
        printf("++ bn_mod_inverse ++\n");
        bn_print(">> a: ", a);
        bn_print(">> n: ", n);
        bn_print(">> result: ", result);
    }

    if (bn_is_one(n)) {
        if (debug) {
            printf("bn_is_one(n) is true\n");
        }
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

    init_zero(&r, MAX_BIGNUM_SIZE);
    init_zero(&nr, MAX_BIGNUM_SIZE);
    init_zero(&t, MAX_BIGNUM_SIZE);
    init_one(&nt, MAX_BIGNUM_SIZE);
    init_zero(&q, MAX_BIGNUM_SIZE);
    init_zero(&tmp, MAX_BIGNUM_SIZE);
    init_zero(&tmp2, MAX_BIGNUM_SIZE);
    init_zero(&tmp3, MAX_BIGNUM_SIZE);

    bn_copy(&r, n);
    /*bn_print("\n[bn_mod_inverse pre_bn_mod] a = ", a);
    bn_print("[bn_mod_inverse pre_bn_mod] n = ", n);
    bn_print("[bn_mod_inverse pre_bn_mod] nr = ", nr);*/
    bn_mod(&nr, a, n); // Compute non-negative remainder of 'a' modulo 'n'
    //bn_print("[bn_mod_inverse post_bn_mod] nr = ", nr);
    unsigned int counter = 0;
    while (!bn_is_zero(&nr)) {
        if (debug) {
            printf("\n### Iteration %d\n", counter);
            bn_print(">> bn_div r = ", &r);
            bn_print(">> bn_div nr = ", &nr); // CHECK
            bn_print(">> bn_div tmp = ", &tmp);
            bn_print(">> bn_div q = ", &q);
        }

        bn_div(&q, &tmp, &r, &nr); // Compute quotient and remainder
        bn_copy(&tmp, &nt);

        nt.top = find_top(&nt, MAX_BIGNUM_SIZE);
        q.top = find_top(&q, MAX_BIGNUM_SIZE);

        //bn_print("\n[0] premul q = ", q);
        //bn_print("[1] premul nt = ", nt);
        bn_mul(&q, &nt, &tmp2); // tmp2 = q * nt
        //bn_print("[2] postmul nt = ", tmp2);        

        //bn_print("[3] presub t = ", t);
        init_zero(&tmp3, MAX_BIGNUM_SIZE);
        bn_subtract(&tmp3, &t, &tmp2); // tmp3 = t - tmp2
        //bn_print("[3.5] postsub tmp2 = ", tmp3);
        bn_copy(&nt, &tmp3); // dst << src
        //bn_print("[4] postsub nt = ", nt);

        bn_copy(&t, &tmp);
        bn_copy(&tmp, &nr);
        //bn_print("[5] premul nr = ", nr);
        //bn_print("[6] premul q = ", q);
        bn_mul(&q, &nr, &tmp2);
        //bn_print("[7] postmul nr = ", tmp2); 
        
        //bn_print("[8] presub r = ", r);
        // set zero to tmp3
        init_zero(&tmp3, MAX_BIGNUM_SIZE);
        bn_subtract(&tmp3, &r, &tmp2); // tmp3 = r - tmp2
        bn_copy(&nr, &tmp3);
        //bn_print("[9] postsub nr = ", nr);

        bn_copy(&r, &tmp);
        /*bn_print("\nq: ", q);
        bn_print("t: ", t);
        bn_print("nt: ", nt);
        bn_print("r: ", r);
        bn_print("nr: ", nr);*/
        if (debug) counter++;
        /*
        if (counter > 160) {
            printf("Counter limit reached\n");
            break;
        }*/
    }

    if (!bn_is_one(&r)) {
        if (debug) printf("No modular inverse exists\n");
        init_zero(result, MAX_BIGNUM_SIZE);
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
        if (debug) printf("bn_mod_inverse negative t\n");
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

    return true;
}

__device__ int point_add(
    EC_POINT *result, 
    EC_POINT *p1, 
    EC_POINT *p2, 
    BIGNUM *p, 
    BIGNUM *a
) {
    bool debug = 1;
    if (debug) {
        printf("++ point_add ++\n");
        bn_print(">> p1.x: ", &p1->x);
        bn_print(">> p1.y: ", &p1->y);
        bn_print(">> p2.x: ", &p2->x);
        bn_print(">> p2.y: ", &p2->y);
        bn_print(">> p: ", p);
        printf(">> p.top: %d\n", p->top);
        printf(">> p.neg: %d\n", p->neg);
        bn_print(">> a: ", a);
        printf(">> a.top: %d\n", a->top);
        printf(">> a.neg: %d\n", a->neg);
    }

    

    // Handle the point at infinity cases
    if (point_is_at_infinity(p1)) {
        copy_point(result, p2);
        // if (debug) 
        if (debug) printf("p1 point at infinity\n");
        return 0;
    }

    // bn_print("\n### p1.x: ", &p1->x);
    // return 0;

    if (point_is_at_infinity(p2)) {
        copy_point(result, p1);
        // if (debug) 
        if (debug) printf("p2 point at infinity\n");
        return 0;
    }

    

    // Initialize temporary BIGNUMs for calculation
    BIGNUM s, x3, y3, tmp1, tmp2, tmp3, two, tmp1_squared;
    init_zero(&s, MAX_BIGNUM_SIZE);
    init_zero(&x3, MAX_BIGNUM_SIZE);
    init_zero(&y3, MAX_BIGNUM_SIZE);
    init_zero(&tmp1, MAX_BIGNUM_SIZE);
    init_zero(&tmp2, MAX_BIGNUM_SIZE);
    init_zero(&tmp3, MAX_BIGNUM_SIZE);
    init_zero(&two, MAX_BIGNUM_SIZE);
    init_zero(&tmp1_squared, MAX_BIGNUM_SIZE);

    
    
    // Case 1: p1 = p2 && p1.y != p2.y
    if (bn_cmp(&p1->x, &p2->x) == 0 && bn_cmp(&p1->y, &p2->y) != 0) {
        // The points are inverses to one another, return point at infinity
        // if (debug) 
        if (debug) printf("The points are inverses to one another\n");
        set_point_at_infinity(result);
        return 0;
    }

    

    // Case 3: p1 == p2
    // TODO: Check, do we need to compare y
    //if (bn_cmp(&p1->x, &p2->x) == 0 && bn_cmp(&p1->y, &p2->y) == 0) {
    if (bn_cmp(&p1->x, &p2->x) == 0) {
        //if (debug) 
        printf("p1.x == p2.x\n");
        // Point doubling
        // BIGNUM two;
        init_zero(&two, MAX_BIGNUM_SIZE);
        bn_set_word(&two, 2);

        // BIGNUM tmp1_squared;
        init_zero(&tmp1_squared, MAX_BIGNUM_SIZE);
        init_zero(&tmp1, MAX_BIGNUM_SIZE);
        bn_copy(&tmp1, &p1->x); // dst << src
        if (debug) {
            bn_print("\n[0] >> bn_mul p1.x: ", &p1->x);
            bn_print("[0] >> bn_mul tmp1: ", &tmp1);
        }
        bn_mul(&p1->x, &tmp1, &tmp1_squared);     // tmp1_squared = p1.x^2 // a * b = product
        if (debug) {
            bn_print("[0] << bn_mul tmp1: ", &tmp1_squared); // ERR
        }

        init_zero(&tmp1, MAX_BIGNUM_SIZE);
        bn_copy(&tmp1, &tmp1_squared); // dst << src
        // Init tmp2 as 3
        init_zero(&tmp2, MAX_BIGNUM_SIZE);
        bn_set_word(&tmp2, 3);
        bn_mul(&tmp1, &tmp2, &tmp1_squared);     // a * b = product
        if (debug) bn_print("\n[1] << bn_mul tmp1_squared: ", &tmp1_squared); // OK

        if (debug) bn_print("\n[2] << bn_add tmp1_squared: ", &tmp1_squared); // 

        init_zero(&tmp1, MAX_BIGNUM_SIZE);
        if (debug) bn_print("\n# [3] >> bn_mod tmp1_squared: ", &tmp1_squared);
        bn_copy(&tmp1, &tmp1_squared); // dst << src        
        if (debug) bn_print("# [3] >> bn_mod tmp1: ", &tmp1);
        init_zero(&tmp1_squared, MAX_BIGNUM_SIZE);
        if (debug) bn_print("[3] >> bn_mod tmp1_squared: ", &tmp1_squared);
        if (debug) bn_print("[3] >> bn_mod tmp1: ", &tmp1);
        if (debug) bn_print("[3] >> bn_mod p: ", p);
        bn_mod(&tmp1_squared, &tmp1, p);           // tmp1_squared = tmp1 mod p
        if (debug) bn_print("[3] << bn_mod tmp1_squared: ", &tmp1_squared); // OK
        if (debug) bn_print("[3] << bn_mod tmp1: ", &tmp1);
        
        init_zero(&tmp2, MAX_BIGNUM_SIZE);
        bn_set_word(&two, 2);
        bn_mul(&p1->y, &two, &tmp2);  // tmp2 = 2 * p1.y
        if (debug) bn_print("\n[4] << bn_mul tmp2: ", &tmp2); // OK

        init_zero(&tmp3, MAX_BIGNUM_SIZE);
        bn_copy(&tmp3, &tmp2); // dst << src
        bn_mod(&tmp2, &tmp3, p);           // tmp2 = tmp3 mod p
        if (debug) bn_print("\n[5] << bn_mod tmp2: ", &tmp2); // OK
        
        init_zero(&tmp3, MAX_BIGNUM_SIZE);
        bn_copy(&tmp3, &tmp2); // dst << src
        init_zero(&tmp2, MAX_BIGNUM_SIZE);
        if (debug) bn_print("\n[6] >> bn_mod_inverse tmp2: ", &tmp2);
        if (debug) bn_print("[6] >> bn_mod_inverse tmp3: ", &tmp3);
        if (debug) bn_print("[6] >> bn_mod_inverse p: ", p);
        bn_mod_inverse(&tmp2, &tmp3, p);  // tmp2 = tmp3 mod p
        if (debug) bn_print("[6] << bn_mod_inverse tmp2: ", &tmp2); // STUCK
        // return 0;//TODO: remove
        init_zero(&tmp3, MAX_BIGNUM_SIZE);
        bn_copy(&tmp3, &tmp1_squared); // dst << src
        if (debug) bn_print("\n[7] >> bn_mul tmp3: ", &tmp3);
        if (debug) bn_print("[7] >> bn_mul tmp2: ", &tmp2);
        bn_mul(&tmp3, &tmp2, &s);  // tmp1 * tmp2 = s
        if (debug) bn_print("[7] << bn_mul s: ", &s); //

        init_zero(&tmp3, MAX_BIGNUM_SIZE);
        bn_copy(&tmp3, &s); // dst << src
        bn_mod(&s, &tmp3, p);  // s = s mod p
        if (debug) bn_print("\n[8] << bn_mod s: ", &s); //

        init_zero(&tmp3, MAX_BIGNUM_SIZE);
        bn_copy(&tmp3, &s); // dst << src
        bn_mul(&tmp3, &tmp3, &x3);  // x3 = s^2
        // bn_print("\n[9] << bn_mul x3: ", &x3); //

        bn_subtract(&x3, &x3, &p1->x);  // x3 = x3 - p1.x
        // bn_print("\n[10] << bn_subtract x3: ", &x3); //

        bn_subtract(&x3, &x3, &p1->x);  // x3 = x3 - p1.x
        // bn_print("\n[11] << bn_subtract x3: ", &x3); //

        init_zero(&tmp3, MAX_BIGNUM_SIZE);
        bn_copy(&tmp3, &x3); // dst << src
        bn_mod(&x3, &tmp3, p);  // x3 = x3 mod p
        // bn_print("\n[12] << bn_mod x3: ", &x3); // OK

        init_zero(&tmp1, MAX_BIGNUM_SIZE);
        // bn_print("[13] >> bn_subtract p1.x: ", &p1->x); //
        // bn_print("[13] >> bn_subtract x3: ", &x3); //
        bn_subtract(&tmp1, &p1->x, &x3);  // tmp1 = p1.x - x3
        // bn_print("\n[13] << bn_subtract tmp1: ", &tmp1); //

        init_zero(&tmp3, MAX_BIGNUM_SIZE);
        bn_copy(&tmp3, &s); // dst << src
        bn_mul(&tmp3, &tmp1, &y3);  // y3 = s * tmp1
        // bn_print("\n[14] << bn_mul y3: ", &y3); //

        //init_zero(&y3, MAX_BIGNUM_SIZE);
        init_zero(&tmp3, MAX_BIGNUM_SIZE);
        bn_copy(&tmp3, &y3); // dst << src
        // bn_print("[15] >> bn_subtract tmp3: ", &tmp3); //
        // bn_print("[15] >> bn_subtract p1.y: ", &p1->y); //
        bn_subtract(&y3, &tmp3, &p1->y);  // y3 = y3 - p1.y
        // bn_print("\n[15] << bn_subtract y3: ", &y3); //

        init_zero(&tmp3, MAX_BIGNUM_SIZE);
        bn_copy(&tmp3, &y3); // dst << src
        bn_mod(&y3, &tmp3, p);  // y3 = y3 mod p
        // bn_print("\n[16] << bn_mod y3: ", &y3); //
    } else {
        // Case 2: p1 != p2
        //if (debug) 
        printf("p1.x != p2.x\n");
        // Regular point addition
        bn_subtract(&tmp1, &p2->y, &p1->y);
        // bn_print("\n[a] << bn_subtract tmp1: ", &tmp1);
        init_zero(&tmp3, MAX_BIGNUM_WORDS);
        bn_copy(&tmp3, &tmp1); // dst << src
        // bn_mod(&tmp1, p, &tmp1);           // tmp1 = (p2.y - p1.y) mod p
        init_zero(&tmp1, MAX_BIGNUM_WORDS);
        // bn_print("\n[c] >> bn_mod tmp3: ", &tmp3);
        // bn_print("\n[c] >> bn_mod p: ", p);        
        bn_mod(&tmp1, &tmp3, p);           // tmp1 = (p2.y - p1.y) mod p 
        // bn_print("\n[c] << bn_mod tmp1: ", &tmp1); // OK
        
        init_zero(&tmp2, MAX_BIGNUM_WORDS);
        bn_subtract(&tmp2, &p2->x, &p1->x);

        init_zero(&tmp3, MAX_BIGNUM_WORDS);
        bn_copy(&tmp3, &tmp2);
        //bn_mod(&tmp2, p, &tmp2);           // tmp2 = (p2.x - p1.x) mod p
        // bn_print("\n[d] >> bn_mod tmp3: ", &tmp3);
        // bn_print("\n[d] >> bn_mod p: ", p);
        bn_mod(&tmp2, &tmp3, p);           // tmp2 = (p2.x - p1.x) mod p
        // bn_print("\n[d] << bn_mod tmp2: ", &tmp2);

        // bn_print("\n[0] >> bn_mod_inverse tmp2: ", &tmp2);
        // bn_print("[0] >> bn_mod_inverse tmp3: ", &tmp3);
        // bn_print("[0] >> bn_mod_inverse p: ", p);
        init_zero(&tmp3, MAX_BIGNUM_WORDS);
        bn_copy(&tmp3, &tmp2);
        init_zero(&tmp2, MAX_BIGNUM_WORDS);
        //bn_mod_inverse(&tmp2, p, &tmp3);   // tmp2 = (p2.x - p1.x)^-1 mod p
        bn_mod_inverse(&tmp2, &tmp3, p);
        // bn_print("\n[1] << bn_mod_inverse tmp2: ", &tmp2); // OK
        // mul(a, b, product)
        //bn_mul(&s, &tmp1, &tmp2);          // s = (p2.y - p1.y) * (p2.x - p1.x)^-1
        // bn_print("\n[2] >> bn_mul s: ", &s);
        // bn_print("\n[2] >> bn_mul tmp1: ", &tmp1);
        // bn_print("\n[2] >> bn_mul tmp2: ", &tmp2);
        init_zero(&s, MAX_BIGNUM_WORDS);
        bn_mul(&tmp1, &tmp2, &s);
        // bn_print("\n[2] << bn_mul s: ", &s);
        // bn_print("\n[2] << bn_mul tmp1: ", &tmp1);
        // bn_print("\n[2] << bn_mul tmp2: ", &tmp2); // OK

        
        init_zero(&tmp2, MAX_BIGNUM_SIZE);
        // bn_print("\n[3a] >> bn_mod s: ", &s);
        bn_copy(&tmp2, &s);
        init_zero(&s, MAX_BIGNUM_SIZE);
        // bn_print("\n[3b] >> bn_mod s: ", &s);
        // bn_print("\n[3] >> bn_mod tmp2: ", &tmp2);
        // bn_print("\n[3] >> bn_mod p: ", p); // OK
        bn_mod(&s, &tmp2, p);                 // s = (p2.y - p1.y) / (p2.x - p1.x) mod p
        // bn_print("\n[3] << bn_mod s: ", &s); // OK

        init_zero(&tmp2, MAX_BIGNUM_WORDS);
        bn_copy(&tmp2, &s);
        // bn_print("\n[4] >> bn_mul x3: ", &x3);
        // bn_print("\n[4] >> bn_mul s: ", &s);
        // bn_print("\n[4] >> bn_mul tmp2: ", &tmp2);
        bn_mul(&s, &tmp2, &x3); // a * b = product // x3 = s^2
        // bn_print("\n[4] << bn_mul x3: ", &x3); // 
        // bn_print("\n[4] << bn_mul s: ", &s);

        //bn_mod(&x3, p, &x3);               // x3 = s^2 mod p
        init_zero(&tmp2, MAX_BIGNUM_WORDS);
        bn_copy(&tmp2, &x3);
        // bn_print("\n[5] >> bn_subtract x3: ", &x3);
        // bn_print("\n[5] >> bn_subtract tmp2: ", &tmp2);
        // print p1.x
        // bn_print("\n[5] >> bn_subtract p1.x: ", &p1->x);
        bn_subtract(&x3, &tmp2, &p1->x); // result = a - b
        // bn_print("\n[5] << bn_subtract x3: ", &x3); //
        bn_subtract(&x3, &x3, &p2->x);          // x3 = s^2 - p1.x - p2.x
        // bn_print("\n[6] << bn_subtract x3: ", &x3);
        
        init_zero(&tmp2, MAX_BIGNUM_SIZE);
        //bn_mod(&x3, p, &x3); // x3 = (s^2 - p1.x - p2.x) mod p tmp2 = 
        bn_copy(&tmp2, &x3);
        // bn_print("\n[7] >> bn_mod x3: ", &x3);
        // bn_print("\n[7] >> bn_mod tmp2: ", &tmp2);
        // bn_print("\n[7] >> bn_mod p: ", p);
        bn_mod(&x3, &tmp2, p); // x3 = tmp2 mod p
        // bn_print("\n[7] << bn_mod x3: ", &x3); // OK

        bn_subtract(&tmp1, &p1->x, &x3);
        // bn_print("\n[8] << bn_subtract tmp1: ", &tmp1); // OK

        //bn_mul(&y3, &s, &tmp1);            // y3 = s * (p1.x - x3)
        bn_mul(&s, &tmp1, &y3); // a * b = product
        // bn_print("\n[9] << bn_mul y3: ", &y3); // OK

        //bn_mod(&y3, p, &y3);               // y3 = s * (p1.x - x3) mod p
        
        init_zero(&tmp2, MAX_BIGNUM_WORDS);
        bn_copy(&tmp2, &y3);
        bn_subtract(&y3, &tmp2, &p1->y);          // y3 = s * (p1.x - x3) - p1.y
        // bn_print("\n[10] << bn_mod y3: ", &y3); // OK

        init_zero(&tmp2, MAX_BIGNUM_WORDS);
        bn_copy(&tmp2, &y3);
        bn_mod(&y3, &tmp2, p);               // y3 = tmp2 mod p
        // bn_print("\n[11] << bn_mod y3: ", &y3);
    }

    // Assign the computed coordinates to the result
    // copy_bn(&result->x, &x3);
    // copy_bn(&result->y, &y3);
    bn_copy(&result->x, &x3);
    bn_copy(&result->y, &y3);

    // Free the dynamically allocated memory
    free_bignum(&s);
    free_bignum(&x3);
    free_bignum(&y3);
    free_bignum(&tmp1);
    free_bignum(&tmp2);
    free_bignum(&tmp3);
    free_bignum(&two);
    free_bignum(&tmp1_squared);

    return 0;
}

__device__ void bignum_to_bit_array_2(BIGNUM *n, unsigned int *bits) {
    int index = 0;
    n->top = find_top(n, MAX_BIGNUM_SIZE);
    for (int i = n->top - 1; i >= 0; --i) {
        BN_ULONG word = n->d[i];
        for (int j = BN_ULONG_NUM_BITS - 1; j >= 0; --j) {
            bits[index++] = (word >> j) & 1;
        }
    }
}

__device__ void bignum_to_bit_array_1(BIGNUM *n, unsigned int *bits) {
    int index = 0;
    n->top = find_top(n, MAX_BIGNUM_SIZE);
    for (int i = 0; i < n->top; ++i) {
        BN_ULONG word = n->d[i];
        for (int j = 0; j < BN_ULONG_NUM_BITS; ++j) {  // Assuming BN_ULONG is 32 bits
            bits[index++] = (word >> j) & 1;
        }
    }
}

__device__ void bignum_to_bit_array(const BIGNUM *n, unsigned int *bits) {
    int index = 0;
    for (int i = 0; i < n->top; ++i) {
        BN_ULONG word = n->d[i];
        //for (int j = 0; j < 32; ++j) {  // Assuming BN_ULONG is 32 bits
        for (int j = 0; j < BN_ULONG_NUM_BITS; ++j) {  // Assuming BN_ULONG is 32 bits
            bits[index++] = (word >> j) & 1;
        }
    }
}

__device__ void init_point_at_infinity(EC_POINT *P) {
    // printf("++ init_point_at_infinity ++\n");
    // For the x and y coordinates of P, we'll set the 'top' to 0,
    // which is our chosen convention for representing the point at infinity.

    init_zero(&P->x, MAX_BIGNUM_SIZE);
    init_zero(&P->y, MAX_BIGNUM_SIZE);

    P->x.top = 1; // No valid 'words' in the BIGNUM representing x
    P->y.top = 1; // No valid 'words' in the BIGNUM representing y
    
    // If 'd' arrays have been allocated, set them to zero as well.
    // memset could potentially be used for this if available and if 'd' is allocated.
    
    // for (int i = 0; i < P->x.dmax; ++i) {
    //     P->x.d[i] = 0;
    // }
    
    // for (int i = 0; i < P->y.dmax; ++i) {
    //     P->y.d[i] = 0;
    // }
    // printf("### mark\n");
    // Alternatively, if you use flags or other conventions for points at infinity,
    // set them accordingly here.
    // printf("-- init_point_at_infinity --\n");
}
