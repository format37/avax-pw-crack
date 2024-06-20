#include <stdio.h>
// Following libraries is for test purposes only
#include <openssl/bn.h>
// #include <string.h>
// #include <stdlib.h>
// #include <stdio.h>
// #include <openssl/bn.h>
#include <string.h>
#include <stdlib.h>

// #define MAX(a, b) ((a) > (b) ? (a) : (b))
// #define MIN(a, b) ((a) < (b) ? (a) : (b))


// #define BN_ULONG unsigned long long
#define BN_ULONG_NUM_BITS 64
// Number of hexadecimal symbols in a BN_ULONG value
// Each hexadecimal symbol represents 4 bits
#define BN_ULONG_NUM_SYMBOLS BN_ULONG_NUM_BITS/4
#define WORDS 2
#define MAX_BIGNUM_SIZE 2 // TODO: test 9

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
            printf(" %016llx", a->d[i]);
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
            printf(" %016llx", a->d[i]);
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

void absolute_subtract(BIGNUM_CUDA *result, BIGNUM_CUDA *a, BIGNUM_CUDA *b) {
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

int bn_div(BIGNUM_CUDA *bn_dividend, BIGNUM_CUDA *bn_divisor, BIGNUM_CUDA *bn_quotient, BIGNUM_CUDA *bn_remainder)
{
    // dividend
    // --------
    // divisor
    printf("++ bn_div ++\n");
    bn_print_bn("bn_dividend = ", bn_dividend);
    bn_print_bn("bn_divisor = ", bn_divisor);
    
    unsigned char dividend_words = find_top(bn_dividend, WORDS);
    unsigned char divisor_words = find_top(bn_divisor, WORDS);
    printf("dividend_words: %d\n", dividend_words);
    printf("divisor_words: %d\n", divisor_words);
    
    unsigned char dividend_significant_symbols = top_significant_symbol(bn_dividend); // OK
    // printf("dividend_significant_symbols: %d\n", dividend_significant_symbols);
    unsigned char divisor_significant_symbols = top_significant_symbol(bn_divisor); // OK
    // printf("divisor_significant_symbols: %d\n", divisor_significant_symbols);
    

    // BN_ULONG divisor_top_word = bn_divisor->d[0];
    BIGNUM_CUDA divisor_top_word;
    init_zero(&divisor_top_word, MAX_BIGNUM_SIZE);
    for (int i = 0; i < WORDS; i++) {
        divisor_top_word.d[i] = bn_divisor->d[i];
    }

    BIGNUM_CUDA shifted_dividend;
    init_zero(&shifted_dividend, MAX_BIGNUM_SIZE);
    for (int i = 0; i < WORDS; i++) {
        shifted_dividend.d[i] = bn_dividend->d[i];
    }
    
    int start_symbol = dividend_significant_symbols - divisor_significant_symbols;
    int end_symbol = dividend_significant_symbols;
    
    bn_print_bn("\nbn_dividend = ", bn_dividend);
    printf("# 0. getting shift from %d to %d of the dividend\n", start_symbol, end_symbol);    
    get_value_from_to(&shifted_dividend, bn_dividend, start_symbol, end_symbol);
    bn_print_bn("shifted_dividend = ", &shifted_dividend);
    
    BN_ULONG subtraction_result = 0;
    BN_ULONG shifted_divisor_multiplicator = 0;
    
    while(1) {
        printf("\n###\n");
        printf("start_symbol = %d\n", start_symbol);
        printf("end_symbol = %d\n", end_symbol);
        
        bn_print_bn("shifted_dividend = ", &shifted_dividend);
        
        if (bn_cmp(&shifted_dividend, bn_divisor) < 0) {

            printf("\n# 1. shifted_dividend is less than ");
            bn_print_bn_line("", bn_divisor);
            printf(" performing additional shift\n");
            if (start_symbol == 0) {
                printf("a. Error: start_symbol is 0\n"); // TODO: check case when start_symbol is 0
                return 0;
            }
            start_symbol -= 1;
            printf("start_symbol = %d\n", start_symbol);
            printf("end_symbol = %d\n", end_symbol);
            BIGNUM_CUDA shifted_dividend_temp;
            init_zero(&shifted_dividend_temp, MAX_BIGNUM_SIZE);
            for (int i = 0; i < WORDS; i++) {
                shifted_dividend_temp.d[i] = bn_dividend->d[i];
            }
            get_value_from_to(&shifted_dividend, &shifted_dividend_temp, start_symbol, end_symbol);
            bn_print_bn("shifted_dividend = ", &shifted_dividend);
        }

        printf("\n# 2. divisor_multiplicator * ");
        bn_print_bn_line("", &divisor_top_word);
        printf(" < ");
        bn_print_bn_line("", &shifted_dividend);

        BN_ULONG dividend_top_word = shifted_dividend.d[0];
        BIGNUM_CUDA multiplied_divisor;
        init_zero(&multiplied_divisor, MAX_BIGNUM_SIZE);
        for (int i = 0; i < WORDS; i++) {
            multiplied_divisor.d[i] = divisor_top_word.d[i];
        }
        BN_ULONG divisor_multiplicator = 1;
        while (multiplied_divisor.d[0] < dividend_top_word) {
            BIGNUM_CUDA result;
            init_zero(&result, MAX_BIGNUM_SIZE);
            bn_add(&result, &multiplied_divisor, &divisor_top_word); // result, a, b
            for (int i = 0; i < WORDS; i++) {
                multiplied_divisor.d[i] = result.d[i];
            }

            divisor_multiplicator++;
        }
        if (multiplied_divisor.d[0] > dividend_top_word) {
            multiplied_divisor.d[0] -= divisor_top_word.d[0];
            divisor_multiplicator--;
        }
        printf("divisor_multiplicator = %016llX\n", divisor_multiplicator);

        printf("\n# 2b assign the divisor_multiplicator %016llX shifted %d times to the quotient\n", divisor_multiplicator, start_symbol);
        bn_quotient->d[0] |= divisor_multiplicator << (4 * start_symbol);

        //printf("\nmultiplied_divisor = %016llX\n", multiplied_divisor);
        bn_print_bn("multiplied_divisor = ", &multiplied_divisor);
        
        printf("\n# 3. %016llX - %016llX\n", dividend_top_word, multiplied_divisor.d[0]);
        subtraction_result = dividend_top_word - multiplied_divisor.d[0];
        printf("subtraction_result = %016llX\n", subtraction_result);

        printf("\n# 4. Assign the next symbol of the dividend to the remainder\n");
        for (int i = 0; i < WORDS; i++) {
            shifted_dividend.d[i] = bn_dividend->d[i];
        }
        dividend_top_word = shifted_dividend.d[0];
        printf("dividend_top_word = %016llX\n", dividend_top_word);

        if (start_symbol == 0) {
            printf("Start_symbol is 0. Finish the division\n");
            break;
        }
        
        printf("start_symbol = %d\n", start_symbol -1);
        BN_ULONG next_symbol = dividend_top_word >> (4 * (start_symbol -1)) & 0xF;
        printf("next_symbol = %X\n", next_symbol);
        
        subtraction_result <<= 4;
        subtraction_result |= next_symbol;
        printf("subtraction_result with next symbol = %016llX\n", subtraction_result);
        shifted_dividend.d[0] = subtraction_result;
        start_symbol -= 1;

        if (start_symbol <= 0) {
            printf("Start_symbol is %d <= 0. Checking if further division is needed.\n", start_symbol);
            if (subtraction_result < bn_divisor->d[0]) {
                printf("Remainder is less than divisor. Finish the division.\n");
                break;
            }
        }
    }

    printf("\n# final: assign the subtraction_result %016llX to the remainder\n", subtraction_result);
    bn_remainder->d[0] = subtraction_result;

    // reverse bn_remainder
    // for (int i = 0; i < WORDS / 2; i++) {
    //     BN_ULONG temp = bn_remainder->d[i];
    //     bn_remainder->d[i] = bn_remainder->d[WORDS - 1 - i];
    //     bn_remainder->d[WORDS - 1 - i] = temp;
    // }

    printf("\n-- bn_div --\n");
    return 1;
}

void openssl_div(BIGNUM_CUDA *bn_dividend, BIGNUM_CUDA *bn_divisor, BIGNUM_CUDA *bn_expected_quotient, BIGNUM_CUDA *bn_expected_remainder) {
    BIGNUM *bn_openssl_dividend = BN_new();
    BIGNUM *bn_openssl_divisor = BN_new();
    BIGNUM *bn_openssl_quotient = BN_new();
    BIGNUM *bn_openssl_remainder = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM_CUDA bn_dividend_tmp;
    BIGNUM_CUDA bn_divisor_tmp;
    init_zero(&bn_dividend_tmp, MAX_BIGNUM_SIZE);
    init_zero(&bn_divisor_tmp, MAX_BIGNUM_SIZE);
    for (int i = 0; i < MAX_BIGNUM_SIZE; i++) {
        bn_dividend_tmp.d[i] = bn_dividend->d[i];
        bn_divisor_tmp.d[i] = bn_divisor->d[i];
    }
    // reverse
    reverse_order(bn_dividend_tmp.d);
    reverse_order(bn_divisor_tmp.d);

    set_bignum_words(bn_openssl_dividend, bn_dividend_tmp.d, MAX_BIGNUM_SIZE);
    set_bignum_words(bn_openssl_divisor, bn_divisor_tmp.d, MAX_BIGNUM_SIZE);

    printf("bn_openssl_dividend = ");
    print_bn_openssl("", bn_openssl_dividend);
    printf("bn_openssl_divisor = ");
    print_bn_openssl("", bn_openssl_divisor);

    BN_div(bn_openssl_quotient, bn_openssl_remainder, bn_openssl_dividend, bn_openssl_divisor, ctx);

    // Convert the results back to your custom BIGNUM_CUDA format
    char *bn_quotient_str = BN_bn2hex(bn_openssl_quotient);
    char *bn_remainder_str = BN_bn2hex(bn_openssl_remainder);

    // Clear the existing values in bn_expected_quotient and bn_expected_remainder
    memset(bn_expected_quotient, 0, sizeof(BIGNUM_CUDA));
    memset(bn_expected_remainder, 0, sizeof(BIGNUM_CUDA));

    // Convert the hexadecimal strings to BIGNUM_CUDA format
    int i = 0;
    int j = strlen(bn_quotient_str);
    while (j > 0) {
        char hex[BN_ULONG_NUM_SYMBOLS + 1] = {0};
        int len = (j >= BN_ULONG_NUM_SYMBOLS) ? BN_ULONG_NUM_SYMBOLS : j;
        strncpy(hex, &bn_quotient_str[j - len], len);
        bn_expected_quotient->d[i++] = strtoull(hex, NULL, 16);
        j -= BN_ULONG_NUM_SYMBOLS;
    }
    bn_expected_quotient->top = i;

    i = 0;
    j = strlen(bn_remainder_str);
    while (j > 0) {
        char hex[BN_ULONG_NUM_SYMBOLS + 1] = {0};
        int len = (j >= BN_ULONG_NUM_SYMBOLS) ? BN_ULONG_NUM_SYMBOLS : j;
        strncpy(hex, &bn_remainder_str[j - len], len);
        bn_expected_remainder->d[i++] = strtoull(hex, NULL, 16);
        j -= BN_ULONG_NUM_SYMBOLS;
    }
    bn_expected_remainder->top = i;

    // // reverse bn_expected_remainder
    // for (int i = 0; i < WORDS / 2; i++) {
    //     BN_ULONG temp = bn_expected_remainder->d[i];
    //     bn_expected_remainder->d[i] = bn_expected_remainder->d[WORDS - 1 - i];
    //     bn_expected_remainder->d[WORDS - 1 - i] = temp;
    // }

    OPENSSL_free(bn_quotient_str);
    OPENSSL_free(bn_remainder_str);

    BN_free(bn_openssl_dividend);
    BN_free(bn_openssl_divisor);
    BN_free(bn_openssl_quotient);
    BN_free(bn_openssl_remainder);
    BN_CTX_free(ctx);
}

int main()
{
    unsigned long long tests_passed = 0;
    BIGNUM_CUDA bn_dividend, bn_divisor, bn_dividend_end, bn_divisor_end;
    init_zero(&bn_dividend, MAX_BIGNUM_SIZE);
    init_zero(&bn_divisor, MAX_BIGNUM_SIZE);
    init_zero(&bn_dividend_end, MAX_BIGNUM_SIZE);
    init_zero(&bn_divisor_end, MAX_BIGNUM_SIZE);
    // dividend
    bn_dividend.d[0] = 0x7e;
    bn_dividend.d[1] = 0xda005671ffb0c893;
    bn_dividend_end.d[0] = 0x7e;
    bn_dividend_end.d[1] = 0xda005671ffb0c894;
    // divisor
    bn_divisor.d[0] = 0x0;
    bn_divisor.d[1] = 0xab2f000e3f00d97;
    bn_divisor_end.d[0] = 0x0;
    bn_divisor_end.d[1] = 0xab2f000e3f00d97;

    // Reverse order of dividend and divisor because of different endianness
    reverse_order(bn_dividend.d);
    reverse_order(bn_dividend_end.d);
    reverse_order(bn_divisor.d);
    reverse_order(bn_divisor_end.d);

    BIGNUM_CUDA bn_quotient, bn_remainder;
    BIGNUM_CUDA bn_one;
            init_zero(&bn_one, MAX_BIGNUM_SIZE);
            bn_one.d[1] = 0x1;
    // reverse bn_one
    for (int i = 0; i < WORDS / 2; i++) {
        BN_ULONG temp = bn_one.d[i];
        bn_one.d[i] = bn_one.d[WORDS - 1 - i];
        bn_one.d[WORDS - 1 - i] = temp;
    }        

    while (bn_cmp(&bn_dividend, &bn_dividend_end) <= 0) {
        while (bn_cmp(&bn_divisor, &bn_divisor_end) <= 0) {

            init_zero(&bn_quotient, MAX_BIGNUM_SIZE);
            init_zero(&bn_remainder, MAX_BIGNUM_SIZE);

            BIGNUM_CUDA bn_expected_quotient;
            BIGNUM_CUDA bn_expected_remainder;
            init_zero(&bn_expected_quotient, MAX_BIGNUM_SIZE);
            init_zero(&bn_expected_remainder, MAX_BIGNUM_SIZE);
            // OpenSSL test
            openssl_div(&bn_dividend, &bn_divisor, &bn_expected_quotient, &bn_expected_remainder);
            
            bn_print_bn("bn_dividend = ", &bn_dividend);
            bn_print_bn("bn_divisor = ", &bn_divisor);

            // CUDA division
            if (!bn_div(&bn_dividend, &bn_divisor, &bn_quotient, &bn_remainder)) {
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

            // Add 1 to divisor
            // bn_divisor.d[1]++; // TODO: Implement bignum addition
            BIGNUM_CUDA bn_divisor_temp;
            init_zero(&bn_divisor_temp, MAX_BIGNUM_SIZE);
            for (int i = 0; i < MAX_BIGNUM_SIZE; i++) {
                bn_divisor_temp.d[i] = bn_divisor.d[i];
            }
            bn_add(&bn_divisor, &bn_divisor_temp, &bn_one);
            tests_passed++;
            // tests_passed = tests_passed + 1;
            // printf("tests_passed: %llu\n", tests_passed);
            // break; // TODO: Remove break
        }
        // Add 1 to dividend
        // bn_dividend.d[1]++; // TODO: Implement bignum addition
        BIGNUM_CUDA bn_dividend_temp;
        init_zero(&bn_dividend_temp, MAX_BIGNUM_SIZE);
        for (int i = 0; i < MAX_BIGNUM_SIZE; i++) {
            bn_dividend_temp.d[i] = bn_dividend.d[i];
        }
        bn_add(&bn_dividend, &bn_dividend_temp, &bn_one);
        // break; // TODO: Remove break
    }

    printf("%llu tests passed_\n", tests_passed);
    bn_print_bn("bn_dividend = ", &bn_dividend);
    bn_print_bn("bn_divisor = ", &bn_divisor);
    return 0;
}