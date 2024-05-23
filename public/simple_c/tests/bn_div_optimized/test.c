#include <stdio.h>

#define BN_ULONG unsigned long long
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
} BIGNUM;

void reverse_order(BN_ULONG *test_values_a) {
    for (size_t j = 0; j < WORDS / 2; j++) {
        BN_ULONG temp_a = test_values_a[j];
        test_values_a[j] = test_values_a[WORDS - 1 - j];
        test_values_a[WORDS - 1 - j] = temp_a;
    }
}

void init_zero(BIGNUM *bn, int capacity) {
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

// void bn_print_bn(const char* msg, BIGNUM* a) {
//     printf("%s", msg);
//     if (a->neg) {
//         printf("-");
//     }
//     for (int i = MAX_BIGNUM_SIZE - 1; i >= 0; i--) {
//         printf("%016llx ", a->d[i]);
//     }
//     printf("\n");
// }
void bn_print_bn(const char* msg, BIGNUM* a) {
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

int bn_cmp(BIGNUM* a, BIGNUM* b) {
    if (a->neg != b->neg) {
        return a->neg ? -1 : 1;
    }

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

// unsigned char find_top(const BN_ULONG *a, int top)
// {
//     while (top > 0 && a[top - 1] == 0) {
//         --top;
//     }
//     return top;
// }
int find_top(const BIGNUM *bn, int max_words) {
    for (int i = MAX_BIGNUM_SIZE - 1; i >= 0; i--) {
        if (bn->d[i] != 0) {
            return i + 1;
        }
    }
    return 1;
}

unsigned char top_word_significant_symbols(BIGNUM *a, const unsigned char top)
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

// unsigned char top_significant_symbol(BIGNUM *a)
// {
//     printf("++ top_significant_symbol ++\n");
//     bn_print_bn(">> a: ", a);
//     // return 0;
//     if (MAX_BIGNUM_SIZE > 256/16) {
//         printf("Error: MAX_BIGNUM_SIZE is bigger than top_word_significant_symbols can handle. Need to increase datatype\n");
//     }
//     unsigned char count = 0;
//     for (int word = MAX_BIGNUM_SIZE - 1; word >= 0; word--) {
//         for (int i = 0; i < BN_ULONG_NUM_SYMBOLS; i++) {
//             //BN_ULONG symbol = a->d[word] >> (4 * i) & 0xF;
//             BN_ULONG temp = a->d[word];
//             printf("\n[%d][%d] temp = %016llX\n", word, i, temp);
//             temp = temp >> (4 * i);
//             printf("[%d][%d] temp = %016llX\n", word, i, temp);
//             BN_ULONG symbol = temp & 0xF;
//             printf("[%d][%d] symbol = %X\n", word, i, symbol);
//             if (symbol == 0) break;
//             count++;
//         }
//     }
//     // for (int i = 0; i < BN_ULONG_NUM_SYMBOLS; i++) {
//     //     BN_ULONG word = a->d[top - 1];
//     //     if ((word >> 4 * i) == 0) break;
//     //     count++;
//     // }
//     printf("-- top_significant_symbol --\n");
//     return count;
// }

unsigned char top_significant_symbol(BIGNUM *a)
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

BN_ULONG get_value_from_to(BN_ULONG a, const int from_in, const int to_in)
{
    // TODO: Replace by BIGNUM
    // get_value_from_to(0xb0c89, 0, 4);  // 0x0C89
    int from = from_in;
    if (from < 0) from = 0;
    int to = to_in;
    if (to > BN_ULONG_NUM_SYMBOLS) to = BN_ULONG_NUM_SYMBOLS;
    printf("get_value_from_to(%016llX, %d, %d)\n", a, from, to);
    BN_ULONG result;
    if (to == BN_ULONG_NUM_SYMBOLS) {
        result = a >> (4 * from);
    } else {
        result = (a >> (4 * from)) & ((1 << (4 * (to - from))) - 1);
    }
    printf("get_value_from_to result = %016llX\n", result);
    return result;
}

int bn_div(BIGNUM *bn_dividend, BIGNUM *bn_divisor, BIGNUM *bn_quotient, BIGNUM *bn_remainder)
{
    // printf("BN_ULONG_NUM_SYMBOLS = %d\n", BN_ULONG_NUM_SYMBOLS);
    // dividend
    // --------
    // divisor
    printf("++ bn_div ++\n");
    unsigned char dividend_words = find_top(&bn_dividend, WORDS);
    unsigned char divisor_words = find_top(&bn_divisor, WORDS);
    printf("dividend_words: %d\n", dividend_words);
    // unsigned char dividend_significant_symbols = top_word_significant_symbols(bn_dividend, dividend_words);
    unsigned char dividend_significant_symbols = top_significant_symbol(bn_dividend);
    // printf("dividend_significant_symbols = %d\n", dividend_significant_symbols);
    // unsigned char divisor_significant_symbols = top_word_significant_symbols(bn_divisor, divisor_words);
    unsigned char divisor_significant_symbols = top_significant_symbol(bn_divisor);
    // printf("divisor_significant_symbols = %d\n", divisor_significant_symbols);

    BN_ULONG divisor_top_word = bn_divisor->d[0]; // TODO: replace by BIGNUM

    // for (int i = 0; i < WORDS; i++) {
    //     quotient[i] = 0;
    //     remainder[i] = 0;
    // }    

    BN_ULONG shifted_dividend[WORDS]; // TODO: replace by BIGNUM
    for (int i = 0; i < WORDS; i++) {
        shifted_dividend[i] = bn_dividend->d[i];
    }
    
    int start_symbol = dividend_significant_symbols - divisor_significant_symbols;
    int end_symbol = dividend_significant_symbols;
    
    printf("\n# 0. getting shift from %d to %d of the dividend\n", start_symbol, end_symbol);
    shifted_dividend[0] = get_value_from_to(bn_dividend->d[0], start_symbol, end_symbol);
    
    BN_ULONG subtraction_result = 0;
    BN_ULONG shifted_divisor_multiplicator = 0;
    
    while(1) {
        printf("\n###\n");
        printf("start_symbol = %d\n", start_symbol);
        printf("end_symbol = %d\n", end_symbol);
        
        bn_print("shifted_dividend = ", shifted_dividend);
        
        if (shifted_dividend[0] < bn_divisor->d[0] ||
            (dividend_words > 1 && shifted_dividend[0] < bn_divisor->d[0])) {

            printf("\n# 1. shifted_dividend is less than %016llX. performing an additional shift\n", bn_divisor->d[0]);
            if (start_symbol == 0) {
                printf("a. Error: start_symbol is 0\n"); // TODO: implement the case when start_symbol is 0
                return 0;
            }
            start_symbol -= 1;
            printf("start_symbol = %d\n", start_symbol);
            printf("end_symbol = %d\n", end_symbol);
            BN_ULONG next_symbol = bn_dividend->d[0] >> (4 * start_symbol) & 0xF;
            printf("next_symbol = %X\n", next_symbol);
            shifted_dividend[dividend_words - 1] <<= 4;
            shifted_dividend[dividend_words - 1] |= next_symbol;
            bn_print("shifted_dividend = ", shifted_dividend);
        }

        printf("\n# 2. divisor_multiplicator * %016llX < %016llX\n", divisor_top_word, shifted_dividend[0]);
        BN_ULONG dividend_top_word = shifted_dividend[0];
        BN_ULONG multiplied_divisor = divisor_top_word;
        BN_ULONG divisor_multiplicator = 1;
        while (multiplied_divisor < dividend_top_word) {
            multiplied_divisor += divisor_top_word;
            divisor_multiplicator++;
        }
        if (multiplied_divisor > dividend_top_word) {
            multiplied_divisor -= divisor_top_word;
            divisor_multiplicator--;
        }
        printf("divisor_multiplicator = %016llX\n", divisor_multiplicator);

        printf("\n# 2b assign the divisor_multiplicator %016llX shifted %d times to the quotient\n", divisor_multiplicator, start_symbol);
        bn_quotient->d[0] |= divisor_multiplicator << (4 * start_symbol);

        printf("\nmultiplied_divisor = %016llX\n", multiplied_divisor);
        
        printf("\n# 3. %016llX - %016llX\n", dividend_top_word, multiplied_divisor);
        subtraction_result = dividend_top_word - multiplied_divisor;
        printf("subtraction_result = %016llX\n", subtraction_result);

        printf("\n# 4. Assign the next symbol of the dividend to the remainder\n");
        for (int i = 0; i < WORDS; i++) {
            shifted_dividend[i] = bn_dividend->d[i];
        }
        dividend_top_word = shifted_dividend[0];
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
        shifted_dividend[0] = subtraction_result;
        start_symbol -= 1;

        if (start_symbol <= 0) {
            printf("Start_symbol is %d <= 0. Checking if further division is needed.\n", start_symbol);
            if (subtraction_result < bn_divisor->d[0]) {
                printf("Remainder is less than divisor. Finish the division.\n");
                break;
            }
        }
    // return 1;
    }

    printf("\n# final: assign the subtraction_result %016llX to the remainder\n", subtraction_result);
    bn_remainder->d[0] = subtraction_result;

    printf("\n-- bn_div --\n");
    return 1;
}

int main()
{
    BN_ULONG tests_passed = 0;
    // BN_ULONG dividend_start = 0xb0c893;
    BN_ULONG dividend_start = 0xda005671ffb0c893;
    // BN_ULONG dividend_start = 0xfedcba9876543210;
    BN_ULONG dividend_end = dividend_start + 10;
    // BN_ULONG divisor_start = 0xd97;
    BN_ULONG divisor_start = 0xab2f000e3f00d97;
    BN_ULONG divisor_end = divisor_start + 10;
    
    for (BN_ULONG dividend_val = dividend_start; dividend_val <= dividend_end; dividend_val++) {
        BN_ULONG dividend[WORDS] = {0x0, dividend_val};
        reverse_order(dividend);

        for (BN_ULONG divisor_val = divisor_start; divisor_val <= divisor_end; divisor_val++) {
            BN_ULONG divisor[WORDS] = {0x0, divisor_val};
            reverse_order(divisor);

            // printf("Testing division: %016llX / %016llX\n", dividend_val, divisor_val);

            BN_ULONG quotient[WORDS];
            BN_ULONG remainder[WORDS];
            // init zero
            for (int i = 0; i < WORDS; i++) {
                quotient[i] = 0;
                remainder[i] = 0;
            }

            BIGNUM bn_dividend, bn_divisor, bn_quotient, bn_remainder;
            init_zero(&bn_dividend, MAX_BIGNUM_SIZE);
            init_zero(&bn_divisor, MAX_BIGNUM_SIZE);
            init_zero(&bn_quotient, MAX_BIGNUM_SIZE);
            init_zero(&bn_remainder, MAX_BIGNUM_SIZE);

            for (int i = 0; i < WORDS; i++) {
                bn_dividend.d[i] = dividend[i];
                bn_divisor.d[i] = divisor[i];
            }

            printf("Testing division:\n");
            bn_print_bn("bn_dividend = ", &bn_dividend);
            bn_print_bn("bn_divisor = ", &bn_divisor);

            if (!bn_div(&bn_dividend, &bn_divisor, &bn_quotient, &bn_remainder)) {
                printf("Error: bn_div failed\n");
                return 1;
            }
            printf("\nResult of division: %016llX / %016llX is\n", dividend_val, divisor_val);
            bn_print("quotient = ", quotient);
            bn_print("remainder = ", remainder);
            printf("\n");

            BN_ULONG expected_quotient = dividend_val / divisor_val;
            BN_ULONG expected_remainder = dividend_val % divisor_val;

            BN_ULONG actual_quotient = bn_quotient.d[0];
            BN_ULONG actual_remainder = bn_remainder.d[0];

            if (actual_quotient != expected_quotient || actual_remainder != expected_remainder) {
                printf("Error: Division %016llX / %016llX test failed\n", dividend_val, divisor_val);
                printf("Expected quotient: %016llX, Actual quotient: %016llX\n", expected_quotient, actual_quotient);
                printf("Expected remainder: %016llX, Actual remainder: %016llX\n", expected_remainder, actual_remainder);
                printf("Tests passed: %llu\n", tests_passed);
                return 1;
            }
            tests_passed++;
        }
    }

    printf("All %llu tests passed\n", tests_passed);
    return 0;
}