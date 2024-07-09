#include <stdio.h>
// Following libraries is for test purposes only
#include <openssl/bn.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

// #define BN_ULONG unsigned long long
#define BN_ULONG_NUM_BITS 64
// Number of hexadecimal symbols in a BN_ULONG value
// Each hexadecimal symbol represents 4 bits
#define BN_ULONG_NUM_SYMBOLS BN_ULONG_NUM_BITS/4
#define WORDS 10
#define MAX_BIGNUM_SIZE 10 // It should be always one more than the actual size to store the edge case carry

typedef struct bignum_st {
  BN_ULONG d[MAX_BIGNUM_SIZE];
  int top;
  int dmax;
  int neg;
  int flags;
} BIGNUM_CUDA;

// max() function for integers
int max(int a, int b) {
    return a > b ? a : b;
}

void set_bignum_words(BIGNUM *bn, const BN_ULONG *words, int num_words) {
    BN_zero(bn);
    for (int i = 0; i < num_words; ++i) {
        BN_add_word(bn, words[i]);
        if (i < num_words - 1) {
            BN_lshift(bn, bn, BN_BITS2);
        }
    }
}

void reverse_order(BN_ULONG *test_values_a) {
    for (size_t j = 0; j < WORDS / 2; j++) {
        BN_ULONG temp_a = test_values_a[j];
        test_values_a[j] = test_values_a[WORDS - 1 - j];
        test_values_a[WORDS - 1 - j] = temp_a;
    }
}

void init_zero(BIGNUM_CUDA *bn, int capacity) {
    for (int i = 0; i < MAX_BIGNUM_SIZE; i++) {
        bn->d[i] = 0;
    }
    bn->top = 1;
    bn->neg = 0;
    bn->dmax = MAX_BIGNUM_SIZE - 1;
}

void bn_print(const char *prefix, const BN_ULONG *a)
{
    printf("%s", prefix);
    for (int i = WORDS - 1; i >= 0; --i) {
        printf("%016llX ", a[i]);
    }
    printf("\n");
}

void print_bn_openssl(const char* label, const BIGNUM* bn) {
    char* bn_str = BN_bn2hex(bn);
    int i = 0;
    while (bn_str[i] == '0' && bn_str[i+1] != '\0') {
        i++;
    }
    printf("%s: %s\n", label, &bn_str[i]);
    OPENSSL_free(bn_str);
}

void bn_print_bn(const char *msg, BIGNUM_CUDA *a) {
    printf("%s", msg);
    if (a->neg) {
        printf("-");  // Handle the case where BIGNUM is negative
    }
    // int size_of_d = sizeof(a->d);
    for (int i = MAX_BIGNUM_SIZE - 1; i >= 0; i--) {
        // Print words up to top - 1 with appropriate formatting
        if (i == MAX_BIGNUM_SIZE - 1) {
            printf("%llx", a->d[i]);
        } else {
            printf("%016llx", a->d[i]);
            //printf("#%016llx", a->d[i]);
        }
    }
    printf("\n");
}

void bn_print_bn_line(const char* msg, BIGNUM_CUDA* a) {
    printf("%s", msg);
    if (a->neg) {
        printf("-");  // Handle the case where BIGNUM is negative
    }
    // int size_of_d = sizeof(a->d);
    for (int i = MAX_BIGNUM_SIZE - 1; i >= 0; i--) {
        // Print words up to top - 1 with appropriate formatting
        if (i == MAX_BIGNUM_SIZE - 1) {
            printf("%llx", a->d[i]);
        } else {
            printf("%016llx", a->d[i]);
            //printf("#%016llx", a->d[i]);
        }
    }
    // printf("\n");
}

int find_top(const BIGNUM_CUDA *bn, int max_words) {
    for (int i = MAX_BIGNUM_SIZE - 1; i >= 0; i--) {
        if (bn->d[i] != 0) {
            return i + 1;
        }
    }
    return 1;
}

int bn_cmp(BIGNUM_CUDA* a, BIGNUM_CUDA* b) {
    // -1: a < b
    // 0: a == b
    // 1: a > b
    if (a->neg != b->neg) {
        return a->neg ? -1 : 1;
    }
    a->top = find_top(a, MAX_BIGNUM_SIZE);
    b->top = find_top(b, MAX_BIGNUM_SIZE);
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

unsigned char top_word_significant_symbols(BIGNUM_CUDA *a, const unsigned char top)
{
    printf("++ top_word_significant_symbols ++\n");
    bn_print_bn(">> a: ", a);
    printf("a[top - 1] = %016llX\n", a->d[top - 1]);
    // return 0;
    if (MAX_BIGNUM_SIZE > 256/16) {
        printf("Error: MAX_BIGNUM_SIZE is bigger than top_word_significant_symbols can handle. Need to increase datatype\n");
    }
    unsigned char count = 0;
    for (int i = 0; i < BN_ULONG_NUM_SYMBOLS; i++) {
        BN_ULONG word = a->d[top - 1];
        if ((word >> 4 * i) == 0) break;
        count++;
    }
    printf("-- top_word_significant_symbols --\n");
    return count;
}

unsigned char top_significant_symbol(BIGNUM_CUDA *a)
{
    // printf("++ top_significant_symbol ++\n");
    // bn_print_bn(">> a: ", a);
    // return 0;
    if (MAX_BIGNUM_SIZE > 256/16) {
        printf("Error: MAX_BIGNUM_SIZE is bigger than top_word_significant_symbols can handle. Need to increase datatype\n");
    }
    unsigned char count = 0;
    int found_non_zero = 0;
    int word = 0;
    int i = 0;
    for (word = MAX_BIGNUM_SIZE - 1; word >= 0; word--) {
        for (i = BN_ULONG_NUM_SYMBOLS - 1; i >= 0; i--) {
            BN_ULONG temp = a->d[word];
            // printf("\n[%d][%d] temp = %016llX\n", word, i, temp);
            temp = temp >> (4 * i);
            // printf("[%d][%d] temp = %016llX\n", word, i, temp);
            BN_ULONG symbol = temp & 0xF;
            // printf("[%d][%d] symbol = %X\n", word, i, symbol);
            if (symbol != 0) {
                found_non_zero = 1;
                // count++;
            } 
            // else if (!found_non_zero) {
            //     count++;
            // }
            if (found_non_zero) {
                break;
            }
        }
        if (found_non_zero) {
            break;
        }
    }
    count = word * BN_ULONG_NUM_SYMBOLS + i + 1;
    // printf("-- top_significant_symbol --\n");
    return count;
}

void get_value_from_to(BIGNUM_CUDA *result, BIGNUM_CUDA *words_original, const int S, const int N) {
    // Reverse words
    BIGNUM_CUDA words;
    init_zero(&words, MAX_BIGNUM_SIZE);
    for (int i = 0; i < MAX_BIGNUM_SIZE; i++) {
        words.d[i] = words_original->d[MAX_BIGNUM_SIZE - 1 - i];
    }
    // Concatenate all words together
    int full_length = MAX_BIGNUM_SIZE * BN_ULONG_NUM_SYMBOLS;
    char all_words[full_length + 1];
    all_words[0] = '\0';
    for (int i = 0; i < MAX_BIGNUM_SIZE; i++) {
        char word[BN_ULONG_NUM_SYMBOLS + 1];
        sprintf(word, "%016llx", words.d[i]);
        strcat(all_words, word);
    }

    // Get the start_symbol
    int start_symbol = full_length - S;
    // Get the final_symbol
    int final_symbol = full_length - N;
    // Get the substring from start_symbol to the final_symbol
    char substring[N - S + 1];
    strncpy(substring, all_words + final_symbol, start_symbol - final_symbol);
    substring[start_symbol - final_symbol] = '\0';

    // Get the length of the substring
    int substring_length = strlen(substring);
    // Calculate the padding
    int padding = full_length - substring_length;

    // Initialize the result to zero
    init_zero(result, MAX_BIGNUM_SIZE);

    // print substring for debugging
    printf("\nSubstring [%d, %d]: %s\n", S, N, substring);

    unsigned char substring_symbol_id = MAX_BIGNUM_SIZE * BN_ULONG_NUM_SYMBOLS - 1;
    // Define the mapping of the char symbol to the BN_ULONG symbol
    BN_ULONG char_to_ulong[256] = {0};
    char_to_ulong['0'] = 0x0;
    char_to_ulong['1'] = 0x1;
    char_to_ulong['2'] = 0x2;
    char_to_ulong['3'] = 0x3;
    char_to_ulong['4'] = 0x4;
    char_to_ulong['5'] = 0x5;
    char_to_ulong['6'] = 0x6;
    char_to_ulong['7'] = 0x7;
    char_to_ulong['8'] = 0x8;
    char_to_ulong['9'] = 0x9;
    char_to_ulong['a'] = 0xa;
    char_to_ulong['b'] = 0xb;
    char_to_ulong['c'] = 0xc;
    char_to_ulong['d'] = 0xd;
    char_to_ulong['e'] = 0xe;
    char_to_ulong['f'] = 0xf;
    // Words: 298b56ae54fe2c3d e75656ab232452bf 0284619f7ea27d52
    // Substring: 4fe2c3d
    unsigned char word = 0;
    unsigned char shifting = 0;
    for (unsigned char i=0;i<substring_length;i++) {
        printf("substring[%d]: %c\n", substring_length-i-1, substring[substring_length-i-1]);
        BN_ULONG ulong_value = char_to_ulong[(unsigned char)substring[substring_length - i - 1]];
        if (shifting == 0) {
            result->d[word] |= ulong_value;
        } else {
            result->d[word] |= ulong_value << (shifting * 4);
        }
        shifting++;
        if (shifting == 16) {
            shifting = 0;
            word++;
        }
    }
    bn_print_bn("from_to: ", result);
}

int absolute_compare(const BIGNUM_CUDA* a, const BIGNUM_CUDA* b) {
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

void absolute_add(BIGNUM_CUDA *result, const BIGNUM_CUDA *a, const BIGNUM_CUDA *b) {
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
        BN_ULONG ai = (i <= a->top) ? a->d[i] : 0;
        BN_ULONG bi = (i <= b->top) ? b->d[i] : 0;

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

void absolute_subtract_wrong(BIGNUM_CUDA *result, BIGNUM_CUDA *a, BIGNUM_CUDA *b) {
    // This function assumes both 'a' and 'b' are positive.
    // It subtracts the absolute values |b| from |a|, where |a| >= |b|.
    // If |a| < |b|, it's the caller's responsibility to set result->neg appropriately.
    bn_print_bn("\n>> absolute_subtract a: ", a);
    bn_print_bn(">> absolute_subtract b: ", b);
    printf("a.top: %d, b.top: %d\n", a->top, b->top);

    int max_top = max(a->top, b->top);
    BN_ULONG borrow = 0;
    result->top = max_top;

    for (int i = 0; i < max_top; ++i) {
        BN_ULONG ai = (i < a->top) ? a->d[i] : 0; // TODO: Check, do we need to replace i < a->top with i <= a->top
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
    bn_print_bn("<< absolute_subtract result: ", result);
}

void absolute_subtract(BIGNUM_CUDA *result, BIGNUM_CUDA *a, BIGNUM_CUDA *b) {
    bn_print_bn("\n>> absolute_subtract a: ", a);
    bn_print_bn(">> absolute_subtract b: ", b);
    printf("a.top: %d, b.top: %d\n", a->top, b->top);

    int max_top = max(a->top, b->top);
    BN_ULONG borrow = 0;
    result->top = max_top;

    for (int i = 0; i < max_top; ++i) {
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

    bn_print_bn("<< absolute_subtract result: ", result);
}

unsigned char bn_add(BIGNUM_CUDA *result, BIGNUM_CUDA *a, BIGNUM_CUDA *b) {
    // Clear the result first.
    // result->top = 0;
    // for (int i = 0; i < MAX_BIGNUM_SIZE; i++) {
    //     result->d[i] = 0;
    // }
    init_zero(result, MAX_BIGNUM_SIZE);

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
    find_top(result, MAX_BIGNUM_SIZE);
    return 1;
}

int bn_cmp_abs(BIGNUM *a, BIGNUM *b) {
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

void bn_subtract(BIGNUM *result, BIGNUM *a, BIGNUM *b) {
    printf("++ bn_subtract ++\n");
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
    a->top = find_top(a, MAX_BIGNUM_SIZE); // This stuck in a loop
    b->top = find_top(b, MAX_BIGNUM_SIZE);
    bn_print(">> a: ", a);
    bn_print(">> b: ", b);

    // If one is negative and the other is positive, it's essentially an addition.
    if (a->neg != b->neg) {
        result->neg = a->neg; // The sign will be the same as the sign of 'a'.
        absolute_add(result, a, b); // Perform the addition of magnitudes here because signs are different.
        // bn_print("result: ", result);
        return;
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
    // return;
    bn_print("<< result: ", result);
    printf("-- bn_subtract --\n");
}

void left_shift(BIGNUM_CUDA *a, int shift) {
    bn_print_bn_line("\nleft_shift: ", a);
    printf(" << %d", shift);
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

    // Update top
    a->top = find_top(a, MAX_BIGNUM_SIZE);
    bn_print_bn_line(" : ", a);
    printf("\n");
}

void right_shift(BIGNUM_CUDA *a, int shift) {
    if (shift == 0) return;  // No shift needed

    int word_shift = shift / BN_ULONG_NUM_BITS;
    int bit_shift = shift % BN_ULONG_NUM_BITS;

    // Handle full word shifts
    if (word_shift > 0) {
        for (int i = 0; i < MAX_BIGNUM_SIZE - word_shift; i++) {
            a->d[i] = a->d[i + word_shift];
        }
        for (int i = MAX_BIGNUM_SIZE - word_shift; i < MAX_BIGNUM_SIZE; i++) {
            a->d[i] = 0;
        }
    }

    // Handle remaining bit shifts
    if (bit_shift > 0) {
        BN_ULONG carry = 0;
        for (int i = MAX_BIGNUM_SIZE - 1; i >= 0; i--) {
            BN_ULONG next_carry = a->d[i] << (BN_ULONG_NUM_BITS - bit_shift);
            a->d[i] = (a->d[i] >> bit_shift) | carry;
            carry = next_carry;
        }
    }

    // Update top
    a->top = find_top(a, MAX_BIGNUM_SIZE);
}

unsigned long long umul64hi(unsigned long long a, unsigned long long b) {
    unsigned long long lo, hi;
    __uint128_t product = (__uint128_t)a * b;
    lo = (unsigned long long)product;
    hi = (unsigned long long)(product >> 64);
    return hi;
}

void bn_mul(BIGNUM *a, BIGNUM *b, BIGNUM *product) {
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
            // unsigned long long lohi = __umul64hi(alow, blow);
            unsigned long long lohi = umul64hi(alow, blow);  // Use the new function here

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

BN_ULONG estimate_quotient_digit(BIGNUM_CUDA *partial_remainder, BIGNUM_CUDA *divisor) {
    int n = MAX_BIGNUM_SIZE - 1;
    BN_ULONG q;

    if (bn_cmp(partial_remainder, divisor) < 0) {
        printf("Estimate: 0 (partial_remainder < divisor)\n");
        return 0;
    }

    if (partial_remainder->d[n] >= divisor->d[n]) {
        q = UINT64_MAX; // 2^64 - 1
    } else {
        q = (partial_remainder->d[n] << 64 | partial_remainder->d[n-1]) / (divisor->d[n] + 1);
    }

    printf("Estimate details: pr[n]=%llu, pr[n-1]=%llu, d[n]=%llu, q=%llu\n", 
           partial_remainder->d[n], partial_remainder->d[n-1], divisor->d[n], q);
    return q;
}

unsigned int find_most_significant_bit(BIGNUM_CUDA *a) {
    printf("++ find_most_significant_bit ++\n");
    bn_print_bn("Input value: ", a);

    unsigned int msb = 0;
    int found = 0;

    // Iterate through words from most significant to least
    for (int i = MAX_BIGNUM_SIZE - 1; i >= 0 && !found; i--) {
        if (a->d[i] != 0) {
            // Found a non-zero word
            unsigned long long word = a->d[i];
            for (int j = BN_ULONG_NUM_BITS - 1; j >= 0; j--) {
                if (word & (1ULL << j)) {
                    // Found the most significant bit in this word
                    msb = i * BN_ULONG_NUM_BITS + j;
                    found = 1;
                    break;
                }
            }
        }
    }

    printf("Most significant bit found at index: %u\n", msb);
    printf("-- find_most_significant_bit --\n");
    return msb;
}

void set_bit(BIGNUM_CUDA *a, unsigned int bit_index) {
    printf("++ set_bit ++\n");
    bn_print_bn("Input value before setting bit: ", a);
    printf("Setting bit at index: %u\n", bit_index);

    // Calculate which word the bit is in
    unsigned int word_index = bit_index / BN_ULONG_NUM_BITS;
    
    // Calculate the position of the bit within the word
    unsigned int bit_position = bit_index % BN_ULONG_NUM_BITS;

    // Check if the word_index is within the bounds of our BIGNUM_CUDA
    if (word_index < MAX_BIGNUM_SIZE) {
        // Set the bit using bitwise OR
        a->d[word_index] |= (1ULL << bit_position);

        // Update the top if necessary
        if (word_index >= a->top) {
            a->top = word_index + 1;
        }
    } else {
        printf("Error: Bit index out of bounds\n");
    }

    bn_print_bn("Value after setting bit: ", a);
    printf("-- set_bit --\n");
}

unsigned char find_most_significant_byte(BIGNUM_CUDA *a) {
    printf("++ find_most_significant_byte ++\n");
    bn_print_bn("Input value: ", a);

    unsigned int msb = 0;
    int found = 0;

    // Iterate through words from most significant to least
    for (int i = MAX_BIGNUM_SIZE - 1; i >= 0 && !found; i--) {
        if (a->d[i] != 0) {
            // Found a non-zero word
            unsigned long long word = a->d[i];
            for (int j = 7; j >= 0; j--) {  // 8 bytes in a 64-bit word
                unsigned char byte = (word >> (j * 8)) & 0xFF;
                if (byte != 0) {
                    // Found the most significant non-zero byte in this word
                    msb = i * 8 + j;
                    found = 1;
                    break;
                }
            }
        }
    }

    printf("Most significant byte found at index: %u\n", msb);
    printf("-- find_most_significant_byte --\n");
    return msb;
}

unsigned int get_bignum_hex_length(BIGNUM_CUDA *a) {
    // printf("++ get_bignum_hex_length ++\n");
    bn_print_bn(">> get_bignum_hex_length: ", a);
    printf("\n");

    int length = 0;
    BIGNUM_CUDA BN_zero;
    init_zero(&BN_zero, MAX_BIGNUM_SIZE);
    BIGNUM_CUDA b;
    init_zero(&b, MAX_BIGNUM_SIZE);
    // Copy a to b
    for (int i = 0; i < MAX_BIGNUM_SIZE; i++) {
        b.d[i] = a->d[i];
    }
    while (bn_cmp(&b, &BN_zero) > 0) {
        // shift right
        right_shift(&b, 4);
        length++;
        // break;
    }
    printf("<< get_bignum_hex_length: %d\n", length);
    printf("\n");
    // printf("-- get_bignum_hex_length --\n");
    return length;
}


unsigned int get_bignum_hex_length_0(BIGNUM_CUDA *a) {
    // printf("++ get_bignum_hex_length ++\n");
    bn_print_bn(">> get_bignum_hex_length: ", a);
    printf("\n");

    unsigned int length = 0;
    int found_non_zero = 0;

    // Iterate through words from most significant to least
    for (int i = MAX_BIGNUM_SIZE - 1; i >= 0; i--) {
        unsigned long long word = a->d[i];
        
        if (!found_non_zero && word != 0) {
            // Found the most significant non-zero word
            found_non_zero = 1;
            
            // Count leading zeros in the most significant non-zero word
            int leading_zeros = __builtin_clzll(word);
            length += (64 - leading_zeros + 3) / 4; // Convert bit count to hex digit count
            
            // No need to process the rest of this word
            continue;
        }
        
        if (found_non_zero) {
            // For all subsequent words, each contributes 16 hex digits
            length += 16;
        }
    }

    // If the number is zero, return 1 (as '0' is represented by one hex digit)
    if (length == 0) {
        length = 1;
    }

    printf("<< get_bignum_hex_length: %u", length);
    printf("\n");
    // printf("-- get_bignum_hex_length --\n");
    return length;
}

int bn_div(BIGNUM_CUDA *bn_dividend, BIGNUM_CUDA *bn_divisor, BIGNUM_CUDA *bn_quotient, BIGNUM_CUDA *bn_remainder)
{
    printf("++ bn_div ++\n");
    bn_print_bn("bn_dividend = ", bn_dividend);
    bn_print_bn("bn_divisor = ", bn_divisor);

    // Handle division by zero
    BIGNUM_CUDA bn_zero;
    init_zero(&bn_zero, MAX_BIGNUM_SIZE);
    if (bn_cmp(bn_divisor, &bn_zero) == 0) {
        printf("Error: Division by zero\n");
        return 0;
    }

    // Store signs and work with absolute values
    int dividend_neg = bn_dividend->neg;
    int divisor_neg = bn_divisor->neg;
    BIGNUM_CUDA abs_dividend, abs_divisor;
    init_zero(&abs_dividend, MAX_BIGNUM_SIZE);
    init_zero(&abs_divisor, MAX_BIGNUM_SIZE);

    // Copy absolute values
    for (int i = 0; i < MAX_BIGNUM_SIZE; i++) {
        abs_dividend.d[i] = bn_dividend->d[i];
        abs_divisor.d[i] = bn_divisor->d[i];
    }
    abs_dividend.neg = 0;
    abs_divisor.neg = 0;

    // Initialize quotient and remainder
    init_zero(bn_quotient, MAX_BIGNUM_SIZE);
    init_zero(bn_remainder, MAX_BIGNUM_SIZE);

    // Handle special cases
    if (bn_cmp(&abs_dividend, &abs_divisor) == 0) {
        bn_quotient->d[0] = 1;
        bn_quotient->top = 1;
        bn_quotient->neg = (dividend_neg != divisor_neg);
        return 1;
    }

    if (bn_cmp(&abs_dividend, &abs_divisor) < 0) {
        // Quotient is 0, remainder is dividend
        for (int i = 0; i < MAX_BIGNUM_SIZE; i++) {
            bn_remainder->d[i] = bn_dividend->d[i];
        }
        bn_remainder->neg = dividend_neg;
        bn_remainder->top = bn_dividend->top;
        return 1;
    }

    // Perform long division
    BIGNUM_CUDA current_dividend;
    init_zero(&current_dividend, MAX_BIGNUM_SIZE);
    int dividend_size = find_top(&abs_dividend, MAX_BIGNUM_SIZE);

    for (int i = dividend_size - 1; i >= 0; i--) {
        // Shift current_dividend left by one word and add next word of dividend
        left_shift(&current_dividend, 64);
        current_dividend.d[0] = abs_dividend.d[i];

        // Find quotient digit
        BN_ULONG q = 0;
        BN_ULONG left = 0, right = UINT64_MAX;
        while (left <= right) {
            BN_ULONG mid = left + (right - left) / 2;
            BIGNUM_CUDA temp, product;
            init_zero(&temp, MAX_BIGNUM_SIZE);
            init_zero(&product, MAX_BIGNUM_SIZE);
            temp.d[0] = mid;

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
        BIGNUM_CUDA temp, product;
        init_zero(&temp, MAX_BIGNUM_SIZE);
        init_zero(&product, MAX_BIGNUM_SIZE);
        temp.d[0] = q;

        bn_mul(&abs_divisor, &temp, &product);
        bn_subtract(&current_dividend, &current_dividend, &product);
    }

    // Set remainder
    for (int i = 0; i < MAX_BIGNUM_SIZE; i++) {
        bn_remainder->d[i] = current_dividend.d[i];
    }

    // Apply correct signs
    bn_quotient->neg = (dividend_neg != divisor_neg);
    bn_remainder->neg = dividend_neg;

    // Normalize results
    bn_quotient->top = find_top(bn_quotient, MAX_BIGNUM_SIZE);
    bn_remainder->top = find_top(bn_remainder, MAX_BIGNUM_SIZE);

    bn_print_bn("bn_quotient = ", bn_quotient);
    bn_print_bn("bn_remainder = ", bn_remainder);
    printf("-- bn_div --\n");
    return 1;
}

void openssl_div(BIGNUM_CUDA *bn_dividend_in, BIGNUM_CUDA *bn_divisor_in, BIGNUM_CUDA *bn_expected_quotient, BIGNUM_CUDA *bn_expected_remainder) {
    BIGNUM *bn_openssl_dividend = BN_new();
    BIGNUM *bn_openssl_divisor = BN_new();
    BIGNUM *bn_openssl_quotient = BN_new();
    BIGNUM *bn_openssl_remainder = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    bn_print_bn("bn_dividend = ", bn_dividend_in);
    bn_print_bn("bn_divisor = ", bn_divisor_in);

    BIGNUM_CUDA bn_dividend;
    BIGNUM_CUDA bn_divisor;
    init_zero(&bn_dividend, MAX_BIGNUM_SIZE);
    init_zero(&bn_divisor, MAX_BIGNUM_SIZE);
    for (int i = 0; i < MAX_BIGNUM_SIZE; i++) {
        bn_dividend.d[i] = bn_dividend_in->d[i];
        bn_divisor.d[i] = bn_divisor_in->d[i];
    }
    bn_dividend.neg = bn_dividend_in->neg;
    bn_divisor.neg = bn_divisor_in->neg;
    // reverse
    reverse_order(bn_dividend.d);
    reverse_order(bn_divisor.d);

    // Convert BIGNUM_CUDA to OpenSSL BIGNUM
    set_bignum_words(bn_openssl_dividend, bn_dividend.d, MAX_BIGNUM_SIZE);
    set_bignum_words(bn_openssl_divisor, bn_divisor.d, MAX_BIGNUM_SIZE);
    BN_set_negative(bn_openssl_dividend, bn_dividend.neg);
    BN_set_negative(bn_openssl_divisor, bn_divisor.neg);

    printf("bn_openssl_dividend = ");
    print_bn_openssl("", bn_openssl_dividend);
    printf("bn_openssl_divisor = ");
    print_bn_openssl("", bn_openssl_divisor);

    // Perform division
    BN_div(bn_openssl_quotient, bn_openssl_remainder, bn_openssl_dividend, bn_openssl_divisor, ctx);
    print_bn_openssl("bn_openssl_quotient = ", bn_openssl_quotient);
    print_bn_openssl("bn_openssl_remainder = ", bn_openssl_remainder);

    // Convert results back to BIGNUM_CUDA format
    init_zero(bn_expected_quotient, MAX_BIGNUM_SIZE);
    init_zero(bn_expected_remainder, MAX_BIGNUM_SIZE);

    // Convert quotient
    bn_expected_quotient->neg = BN_is_negative(bn_openssl_quotient);
    bn_expected_quotient->top = BN_num_bytes(bn_openssl_quotient);
    unsigned char *temp_buffer = (unsigned char *)malloc(bn_expected_quotient->top);
    BN_bn2bin(bn_openssl_quotient, temp_buffer);
    for (int i = 0; i < bn_expected_quotient->top; i++) {
        bn_expected_quotient->d[i / 8] |= ((BN_ULONG)temp_buffer[bn_expected_quotient->top - 1 - i]) << (8 * (i % 8));
    }
    free(temp_buffer);

    // Convert remainder
    bn_expected_remainder->neg = BN_is_negative(bn_openssl_remainder);
    bn_expected_remainder->top = BN_num_bytes(bn_openssl_remainder);
    temp_buffer = (unsigned char *)malloc(bn_expected_remainder->top);
    BN_bn2bin(bn_openssl_remainder, temp_buffer);
    for (int i = 0; i < bn_expected_remainder->top; i++) {
        bn_expected_remainder->d[i / 8] |= ((BN_ULONG)temp_buffer[bn_expected_remainder->top - 1 - i]) << (8 * (i % 8));
    }
    free(temp_buffer);

    // Print results
    bn_print_bn("bn_expected_quotient = ", bn_expected_quotient);
    bn_print_bn("bn_expected_remainder = ", bn_expected_remainder);

    // Clean up
    BN_free(bn_openssl_dividend);
    BN_free(bn_openssl_divisor);
    BN_free(bn_openssl_quotient);
    BN_free(bn_openssl_remainder);
    BN_CTX_free(ctx);
}

// Helper function to generate a random 64-bit unsigned integer
BN_ULONG rand_uint64() {
    return ((BN_ULONG)rand() << 32) | rand();
}

// Generate a random BIGNUM_CUDA with a specified number of words
void generate_random_bignum(BIGNUM_CUDA *bn, int num_words) {
    init_zero(bn, MAX_BIGNUM_SIZE);
    for (int i = 0; i < num_words; i++) {
        bn->d[i] = rand_uint64();
    }
    bn->top = find_top(bn, MAX_BIGNUM_SIZE);
    // Set .neg flag randomly 0 or 1 (negative)
    bn->neg = (rand() % 2 == 0) ? 0 : 1; // TODO: Uncomment this line
}

// Ensure divisor is less than or equal to dividend
void adjust_divisor_non_abs(BIGNUM_CUDA *divisor, BIGNUM_CUDA *dividend) {
    while (bn_cmp(divisor, dividend) > 0) {
        for (int i = 0; i < MAX_BIGNUM_SIZE; i++) {
            divisor->d[i] >>= 1;
        }
        divisor->top = find_top(divisor, MAX_BIGNUM_SIZE);
    }
}

void adjust_divisor(BIGNUM_CUDA *divisor, BIGNUM_CUDA *dividend) {
    // Create temporary variables for absolute values
    BIGNUM_CUDA abs_divisor, abs_dividend;
    init_zero(&abs_divisor, MAX_BIGNUM_SIZE);
    init_zero(&abs_dividend, MAX_BIGNUM_SIZE);

    // Copy absolute values
    for (int i = 0; i < MAX_BIGNUM_SIZE; i++) {
        abs_divisor.d[i] = divisor->d[i];
        abs_dividend.d[i] = dividend->d[i];
    }
    abs_divisor.neg = 0;
    abs_dividend.neg = 0;

    // Adjust based on absolute values
    while (bn_cmp(&abs_divisor, &abs_dividend) > 0) {
        for (int i = 0; i < MAX_BIGNUM_SIZE; i++) {
            abs_divisor.d[i] >>= 1;
        }
        abs_divisor.top = find_top(&abs_divisor, MAX_BIGNUM_SIZE);
    }

    // Copy adjusted value back to divisor, preserving the original sign
    for (int i = 0; i < MAX_BIGNUM_SIZE; i++) {
        divisor->d[i] = abs_divisor.d[i];
    }
    divisor->top = abs_divisor.top;
    // Note: We don't change divisor->neg here, preserving the original sign
}



int main_f()
{
    unsigned long long tests_passed = 0;
    BIGNUM_CUDA bn_dividend, bn_divisor, bn_dividend_end, bn_divisor_end;
    init_zero(&bn_dividend, MAX_BIGNUM_SIZE);
    init_zero(&bn_divisor, MAX_BIGNUM_SIZE);
    init_zero(&bn_dividend_end, MAX_BIGNUM_SIZE);
    init_zero(&bn_divisor_end, MAX_BIGNUM_SIZE);

    bn_dividend.d[0] = 0x0;
    bn_dividend.d[1] = 0x0;
    bn_dividend.d[2] = 0x0;
    bn_dividend.d[3] = 0x0;
    bn_dividend.d[4] = 0x0;
    bn_dividend.d[5] = 0x0;
    bn_dividend.d[6] = 0x0;
    bn_dividend.d[7] = 0x0;
    bn_dividend.d[8] = 0x72b47b314e91753a;
    bn_dividend.d[9] = 0x3f38e8c61b9ed846;

    // set negative flag
    bn_dividend.neg = 1;

    // Fill bn_dividend_end with the same values
    for (int i = 0; i < MAX_BIGNUM_SIZE; i++) {
        bn_dividend_end.d[i] = bn_dividend.d[i];
    }
    // copy negative flag
    bn_dividend_end.neg = bn_dividend.neg;

    bn_divisor.d[0] = 0x0;
    bn_divisor.d[1] = 0x0;
    bn_divisor.d[2] = 0x0;
    bn_divisor.d[3] = 0x0;
    bn_divisor.d[4] = 0x0;
    bn_divisor.d[5] = 0x0;
    bn_divisor.d[6] = 0x0;
    bn_divisor.d[7] = 0x0;
    bn_divisor.d[8] = 0xd1075ad5b373c6d;
    bn_divisor.d[9] = 0x1dfd6bc539e3e809;

    // set negative flag
    bn_divisor.neg = 0;

    // Fill bn_divisor_end with the same values
    for (int i = 0; i < MAX_BIGNUM_SIZE; i++) {
        bn_divisor_end.d[i] = bn_divisor.d[i];
    }
    // copy negative flag
    bn_divisor_end.neg = bn_divisor.neg;

    BIGNUM_CUDA bn_one;
    init_zero(&bn_one, MAX_BIGNUM_SIZE);
    bn_one.d[0] = 0x0;
    bn_one.d[1] = 0x0;
    bn_one.d[2] = 0x0;
    bn_one.d[3] = 0x0;
    bn_one.d[4] = 0x0;
    bn_one.d[5] = 0x0;
    bn_one.d[6] = 0x0;
    bn_one.d[7] = 0x0;
    bn_one.d[8] = 0x1;
    reverse_order(bn_one.d);

    // Reverse order of dividend and divisor because of different endianness
    reverse_order(bn_dividend.d);
    reverse_order(bn_dividend_end.d);
    reverse_order(bn_divisor.d);
    reverse_order(bn_divisor_end.d);

    BIGNUM_CUDA bn_quotient, bn_remainder;
    BIGNUM_CUDA current_dividend, current_divisor;
    init_zero(&current_dividend, MAX_BIGNUM_SIZE);
    init_zero(&current_divisor, MAX_BIGNUM_SIZE);

    // Copy initial dividend to current_dividend
    for (int i = 0; i < MAX_BIGNUM_SIZE; i++) {
        current_dividend.d[i] = bn_dividend.d[i];
    }
    // copy negative flag
    current_dividend.neg = bn_dividend.neg;

    // while (bn_cmp(&current_dividend, &bn_dividend_end) <= 0) {
    while (1) {
        // Reset current_divisor to initial divisor for each new dividend
        for (int i = 0; i < MAX_BIGNUM_SIZE; i++) {
            current_divisor.d[i] = bn_divisor.d[i];
        }
        // copy negative flag
        current_divisor.neg = bn_divisor.neg;

        // while (bn_cmp(&current_divisor, &bn_divisor_end) <= 0) {
        while (1) {
            init_zero(&bn_quotient, MAX_BIGNUM_SIZE);
            init_zero(&bn_remainder, MAX_BIGNUM_SIZE);

            BIGNUM_CUDA bn_expected_quotient, bn_expected_remainder;
            init_zero(&bn_expected_quotient, MAX_BIGNUM_SIZE);
            init_zero(&bn_expected_remainder, MAX_BIGNUM_SIZE);

            // OpenSSL test
            openssl_div(&current_dividend, &current_divisor, &bn_expected_quotient, &bn_expected_remainder);
            
            bn_print_bn("current_dividend = ", &current_dividend);
            bn_print_bn("current_divisor = ", &current_divisor);

            // CUDA division
            if (!bn_div(&current_dividend, &current_divisor, &bn_quotient, &bn_remainder)) {
                printf("Error: bn_div failed\n");
                return 1;
            }
            
            printf("CUDA test values:\n");
            bn_print_bn("bn_dividend = ", &bn_dividend);
            bn_print_bn("bn_divisor = ", &bn_divisor);

            if (bn_cmp(&bn_quotient, &bn_expected_quotient) != 0 || bn_cmp(&bn_remainder, &bn_expected_remainder) != 0) {
                printf("Error: Division test failed\n");
                printf("\nExpected quotient: ");
                bn_print_bn("", &bn_expected_quotient);
                printf("Actual quotient: ");
                bn_print_bn("", &bn_quotient);
                printf("\nExpected remainder: ");
                bn_print_bn("", &bn_expected_remainder);
                printf("Actual remainder: ");
                bn_print_bn("", &bn_remainder);
                printf("\nTests passed: %llu\n", tests_passed);
                return 1;
            }
            else {
                printf("OK\n");
                // Print expected quotient and remainder as bn
                bn_print_bn("expected quotient: ", &bn_expected_quotient);
                bn_print_bn("expected remainder: ", &bn_expected_remainder);
                // Print dividend and remainder as bn
                bn_print_bn("quotient: ", &bn_quotient);
                bn_print_bn("remainder: ", &bn_remainder);
                printf("\n");
            }

            tests_passed++;

            // Increment divisor
            if (bn_cmp(&current_divisor, &bn_divisor_end) < 0) {
                BIGNUM_CUDA temp_divisor;
                init_zero(&temp_divisor, MAX_BIGNUM_SIZE);
                for (int i = 0; i < MAX_BIGNUM_SIZE; i++) {
                    temp_divisor.d[i] = current_divisor.d[i];
                }
                // copy negative flag
                temp_divisor.neg = current_divisor.neg;

                bn_add(&current_divisor, &temp_divisor, &bn_one);
            } else {
                break;  // Move to next dividend if we've reached the end of divisors
            }
            break; // negative numbers issue testing
        }

        // Increment dividend
        if (bn_cmp(&current_dividend, &bn_dividend_end) < 0) {
            BIGNUM_CUDA temp_dividend;
            init_zero(&temp_dividend, MAX_BIGNUM_SIZE);
            for (int i = 0; i < MAX_BIGNUM_SIZE; i++) {
                temp_dividend.d[i] = current_dividend.d[i];
            }
            // copy negative flag
            temp_dividend.neg = current_dividend.neg;

            bn_add(&current_dividend, &temp_dividend, &bn_one);
        } else {
            break;  // End the loop if we've tested all dividends
        }
        break; // negative numbers issue testing
    }

    printf("%llu tests passed\n", tests_passed);
    bn_print_bn("Final dividend = ", &current_dividend);
    bn_print_bn("Final divisor = ", &current_divisor);
    return 0;
}

int main() {
    srand(time(NULL));  // Initialize random seed

    int N = 10000;  // Number of tests to run
    unsigned long long tests_passed = 0;

    for (int test = 0; test < N; test++) {
        BIGNUM_CUDA bn_dividend, bn_divisor;
        
        // Randomly decide the number of words for dividend (1 to 9)
        int dividend_words = rand() % 9 + 1;
        generate_random_bignum(&bn_dividend, dividend_words);

        // Generate divisor with same or fewer words
        int divisor_words = rand() % dividend_words + 1;
        generate_random_bignum(&bn_divisor, divisor_words);

        // Ensure divisor is less than or equal to dividend
        adjust_divisor(&bn_divisor, &bn_dividend);

        BIGNUM_CUDA bn_quotient, bn_remainder;
        BIGNUM_CUDA bn_expected_quotient, bn_expected_remainder;

        // OpenSSL test
        openssl_div(&bn_dividend, &bn_divisor, &bn_expected_quotient, &bn_expected_remainder);

        // CUDA division
        if (!bn_div(&bn_dividend, &bn_divisor, &bn_quotient, &bn_remainder)) {
            printf("Error: bn_div failed\n");
            return 1;
        }
        // int msh_diff = get_bignum_hex_length(&bn_dividend) - get_bignum_hex_length(&bn_divisor);

        if (bn_cmp(&bn_quotient, &bn_expected_quotient) != 0 || bn_cmp(&bn_remainder, &bn_expected_remainder) != 0) {
            printf("Error: Division test failed for test %d\n", test + 1);
            printf("Dividend: ");
            bn_print_bn("", &bn_dividend);
            printf("Divisor: ");
            bn_print_bn("", &bn_divisor);
            printf("Expected quotient: ");
            bn_print_bn("", &bn_expected_quotient);
            printf("Actual quotient: ");
            bn_print_bn("", &bn_quotient);
            printf("Expected remainder: ");
            bn_print_bn("", &bn_expected_remainder);
            printf("Actual remainder: ");
            bn_print_bn("", &bn_remainder);
            printf("Tests passed before failure: %llu\n", tests_passed);
            // print most signioficant hex diff
            // printf("####FAIL %d\n", msh_diff);
            // printf("Most significant hex dividend: %d\n", get_bignum_hex_length(&bn_dividend));
            // printf("Most significant hex divisor: %d\n", get_bignum_hex_length(&bn_divisor));            
            return 1;
        }
        // printf("Most significant hex dividend: %d\n", get_bignum_hex_length(&bn_dividend));
        // printf("Most significant hex divisor: %d\n", get_bignum_hex_length(&bn_divisor));
        // printf("####OK %d\n", msh_diff);
        tests_passed++;
    }

    printf("%llu out of %d tests passed\n", tests_passed, N);
    return 0;
}