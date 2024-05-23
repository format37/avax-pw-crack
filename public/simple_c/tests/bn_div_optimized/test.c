#include <stdio.h>

#define BN_ULONG unsigned long long
#define BN_ULONG_NUM_BITS 64
#define BN_ULONG_NUM_SYMBOLS BN_ULONG_NUM_BITS/4
#define WORDS 2

void reverse_order(BN_ULONG *test_values_a) {
    for (size_t j = 0; j < WORDS / 2; j++) {
        BN_ULONG temp_a = test_values_a[j];
        test_values_a[j] = test_values_a[WORDS - 1 - j];
        test_values_a[WORDS - 1 - j] = temp_a;
    }
}

void bn_print(const char *prefix, const BN_ULONG *a)
{
    printf("%s", prefix);
    for (int i = WORDS - 1; i >= 0; --i) {
        printf("%016llX ", a[i]);
    }
    printf("\n");
}

unsigned char find_top(const BN_ULONG *a, int top)
{
    while (top > 0 && a[top - 1] == 0) {
        --top;
    }
    return top;
}

unsigned char top_word_significant_symbols(const BN_ULONG *a, const unsigned char top)
{
    char count = 0;
    for (int i = 0; i < BN_ULONG_NUM_SYMBOLS; i++) {
        BN_ULONG word = a[top - 1];
        if ((word >> 4 * i) == 0) break;
        count++;
    }
    return count;
}



BN_ULONG get_value_from_to(const BN_ULONG a, const char from_in, const char to)
{
    // get_value_from_to(0xb0c89, 0, 4);  // 0x0C89
    char from = from_in;
    if (from < 0) from = 0;
    return (a >> (4 * from)) & ((1 << (4 * (to - from))) - 1);
}

int bn_div(const BN_ULONG *dividend, const BN_ULONG *divisor, BN_ULONG *quotient, BN_ULONG *remainder)
{
    printf("BN_ULONG_NUM_SYMBOLS = %d\n", BN_ULONG_NUM_SYMBOLS);
    // dividend
    // --------
    // divisor
    printf("++ bn_div ++\n");
    unsigned char dividend_words = find_top(dividend, WORDS);
    unsigned char divisor_words = find_top(divisor, WORDS);
    unsigned char dividend_significant_symbols = top_word_significant_symbols(dividend, dividend_words);
    unsigned char divisor_significant_symbols = top_word_significant_symbols(divisor, divisor_words);

    BN_ULONG divisor_top_word = divisor[divisor_words - 1];

    for (int i = 0; i < WORDS; i++) {
        quotient[i] = 0;
        remainder[i] = 0;
    }

    BN_ULONG shifted_dividend[WORDS];
    for (int i = 0; i < WORDS; i++) {
        shifted_dividend[i] = dividend[i];
    }

    char start_symbol = dividend_significant_symbols - divisor_significant_symbols;
    char end_symbol = dividend_significant_symbols;

    printf("\n# 0. getting shift from %d to %d of the dividend\n", start_symbol, end_symbol);
    shifted_dividend[dividend_words - 1] = get_value_from_to(dividend[dividend_words - 1], start_symbol, end_symbol);
    
    BN_ULONG subtraction_result = 0;
    BN_ULONG shifted_divisor_multiplicator = 0;

    while(1) {
        printf("\n###\n");
        printf("start_symbol = %d\n", start_symbol);
        printf("end_symbol = %d\n", end_symbol);
        
        bn_print("shifted_dividend = ", shifted_dividend);

        if (shifted_dividend[dividend_words - 1] < divisor[divisor_words - 1] ||
            (dividend_words > 1 && shifted_dividend[dividend_words - 2] < divisor[divisor_words - 2])) {

            printf("\n# 1. shifted_dividend is less than %016llX. performing an additional shift\n", divisor[divisor_words - 1]);
            if (start_symbol == 0) {
                printf("a. Error: start_symbol is 0\n"); // TODO: implement the case when start_symbol is 0
                return 0;
            }
            start_symbol -= 1;
            printf("start_symbol = %d\n", start_symbol);
            printf("end_symbol = %d\n", end_symbol);
            BN_ULONG next_symbol = dividend[dividend_words - 1] >> (4 * start_symbol) & 0xF;
            printf("next_symbol = %X\n", next_symbol);
            shifted_dividend[dividend_words - 1] <<= 4;
            shifted_dividend[dividend_words - 1] |= next_symbol;
            bn_print("shifted_dividend = ", shifted_dividend);
        }

        printf("\n# 2. divisor_multiplicator * %016llX < %016llX\n", divisor_top_word, shifted_dividend[dividend_words - 1]);
        BN_ULONG dividend_top_word = shifted_dividend[dividend_words - 1];
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
        quotient[dividend_words - 1] |= divisor_multiplicator << (4 * start_symbol);

        // // Step 1: Calculate the shift amount
        // int shift_amount = 4 * start_symbol;
        // printf("shift_amount = %d\n", shift_amount);
        // // Step 2: Shift the divisor_multiplicator by the shift amount
        // shifted_divisor_multiplicator = divisor_multiplicator << shift_amount;
        // printf("shifted_divisor_multiplicator = %016llX\n", shifted_divisor_multiplicator);
        // // Step 3: Assign the shifted divisor_multiplicator to the quotient using bitwise OR
        // quotient[dividend_words - 1] |= shifted_divisor_multiplicator;
        // printf("quotient[dividend_words - 1] = %016llX\n", quotient[dividend_words - 1]);

        printf("\nmultiplied_divisor = %016llX\n", multiplied_divisor);

        printf("\n# 3. %016llX - %016llX\n", dividend_top_word, multiplied_divisor);
        subtraction_result = dividend_top_word - multiplied_divisor;
        printf("subtraction_result = %016llX\n", subtraction_result);

        printf("\n# 4. Assign the next symbol of the dividend to the remainder\n");
        for (int i = 0; i < WORDS; i++) {
            shifted_dividend[i] = dividend[i];
        }
        dividend_top_word = shifted_dividend[dividend_words - 1];
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
        shifted_dividend[dividend_words - 1] = subtraction_result;
        start_symbol -= 1;

        if (start_symbol <= 0) {
            printf("Start_symbol is %d <= 0. Checking if further division is needed.\n", start_symbol);
            if (subtraction_result < divisor[divisor_words - 1]) {
                printf("Remainder is less than divisor. Finish the division.\n");
                break;
            }
        }
        ;
    }

    printf("\n# final: assign the subtraction_result to the remainder\n");
    remainder[dividend_words - 1] = subtraction_result;

    printf("\n-- bn_div --\n");
    return 1;
}

int main()
{
    BN_ULONG tests_passed = 0;
    // BN_ULONG dividend_start = 0xb0c893;
    BN_ULONG dividend_start = 0xda005671ffb0c893;
    BN_ULONG dividend_end = dividend_start + 100;
    BN_ULONG divisor_start = 0xd97;
    // BN_ULONG divisor_start = 0xe3f00d97; // ERR
    BN_ULONG divisor_end = divisor_start + 100;
    
    for (BN_ULONG dividend_val = dividend_start; dividend_val <= dividend_end; dividend_val++) {
        BN_ULONG dividend[WORDS] = {0, dividend_val};
        reverse_order(dividend);

        for (BN_ULONG divisor_val = divisor_start; divisor_val <= divisor_end; divisor_val++) {
            BN_ULONG divisor[WORDS] = {0, divisor_val};
            reverse_order(divisor);

            printf("Testing division: %016llX / %016llX\n", dividend_val, divisor_val);

            BN_ULONG quotient[WORDS];
            BN_ULONG remainder[WORDS];
            // init zero
            for (int i = 0; i < WORDS; i++) {
                quotient[i] = 0;
                remainder[i] = 0;
            }
            if (!bn_div(dividend, divisor, quotient, remainder)) {
                printf("Error: bn_div failed\n");
                return 1;
            }
            printf("\nResult of division: %016llX / %016llX is\n", dividend_val, divisor_val);
            bn_print("quotient = ", quotient);
            bn_print("remainder = ", remainder);
            printf("\n");

            BN_ULONG expected_quotient = dividend_val / divisor_val;
            BN_ULONG expected_remainder = dividend_val % divisor_val;

            BN_ULONG actual_quotient = quotient[WORDS - 2];
            BN_ULONG actual_remainder = remainder[WORDS - 2];

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