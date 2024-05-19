#include <stdio.h>

#define BN_ULONG unsigned long long
#define BN_ULONG_NUM_BITS 64
#define BN_ULONG_NUM_SYMBOLS BN_ULONG_NUM_BITS/8
#define WORDS 2

void reverse_order(BN_ULONG *test_values_a) {
    for (size_t j = 0; j < WORDS / 2; j++) {
        BN_ULONG temp_a = test_values_a[j];
        test_values_a[j] = test_values_a[WORDS - 1 - j];
        test_values_a[WORDS - 1 - j] = temp_a;
    }
}

void bn_print_reversed_words(const char *prefix, const BN_ULONG *a)
{
    printf("%s", prefix);
    for (int i = 0; i < WORDS; ++i) {
        printf("%016llX ", a[i]);
    }
    printf("\n");
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

int get_msb_bit(BN_ULONG *n) {
    unsigned char top = find_top(n, WORDS);
    if (top == 0) return -1; // All zero

    BN_ULONG word = n[top - 1];
    if (word == 0) return -1; // Top word should not be zero

    int msb_bit = (top - 1) * BN_ULONG_NUM_BITS;
    while (word != 0) {
        word >>= 1;
        msb_bit++;
    }

    return msb_bit - 1;
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

int bn_div(const BN_ULONG *dividend, const BN_ULONG *divisor, BN_ULONG *quotient, BN_ULONG *remainder)
{
    printf("++ bn_div ++\n");
    printf("dividend top: %d\n", find_top(dividend, WORDS));
    printf("divisor top: %d\n", find_top(divisor, WORDS));
    unsigned char dividend_top = find_top(dividend, WORDS);
    unsigned char divisor_top = find_top(divisor, WORDS);
    unsigned char dividend_word_top = top_word_significant_symbols(dividend, dividend_top);
    unsigned char divisor_word_top = top_word_significant_symbols(divisor, divisor_top);
    printf("dividend count_significant_symbols: %d\n", dividend_word_top);
    printf("divisor count_significant_symbols: %d\n", divisor_word_top);
    // Suppose that dividend and divisor have the same top equals to 1
    // Suppose that dividend is greater than divisor

    BN_ULONG divisor_word = divisor[divisor_top - 1]; // Suppose that divisor have only first word

    // Step 1: Shift the dividend dividend_word_top - divisor_word_top times to the right
    BN_ULONG shifted_dividend[WORDS];
    for (int i = 0; i < WORDS; i++) {
        shifted_dividend[i] = dividend[i];
    }
    // BN_ULONG shifted_divisor[WORDS];
    // for (int i = 0; i < WORDS; i++) {
    //     shifted_divisor[i] = divisor[i];
    // }
    shifted_dividend[dividend_top - 1] = dividend[dividend_top - 1] >> 4 * (dividend_word_top - divisor_word_top);
    bn_print("shifted_dividend = ", shifted_dividend);
    // bn_print("shifted_divisor = ", shifted_divisor);
    if (shifted_dividend[dividend_top - 1] < divisor[divisor_top - 1]) {
        printf("dividend >> 4 is less than divisor. performing an additional shift\n"); // TODO: check the word edge case
        shifted_dividend[dividend_top - 1] = dividend[dividend_top - 1] >> 4 * (dividend_word_top - divisor_word_top - 1);
    }
    bn_print("shifted_dividend = ", shifted_dividend);
    
    // Step 2: Multiplication of the shifted dividend by the divisor
    // unsigned long long shifted_quotient;
    BN_ULONG shifted_remainder;
    // shifted_quotient = shifted_dividend[dividend_top - 1] / shifted_divisor[divisor_top - 1];
    // shifted_remainder = shifted_dividend[dividend_top - 1] % shifted_divisor[divisor_top - 1];
    // Classic division and modulo is not available for big numbers. Therefore we use the addiction and comparison
    BN_ULONG shifted_dividend_word = shifted_dividend[dividend_top - 1];
    BN_ULONG multiplied_quotient = divisor_word;

    unsigned char multiplication_times = 0;
    while (multiplied_quotient < shifted_dividend_word) {
        multiplied_quotient += divisor_word;
        multiplication_times++;
    }
    if (multiplied_quotient > shifted_dividend_word) {
        multiplied_quotient -= divisor_word;
    }
    printf("multiplication_times = %d\n", multiplication_times);
    printf("multiplied_quotient = %llu\n", multiplied_quotient);

    // Step 3: Subtraction of the multiplied divisor from the shifted dividend
    BN_ULONG sub_remainder = shifted_dividend_word - multiplied_quotient;
    printf("sub_remainder = %llu\n", sub_remainder);

    // Step 4: Check if the subtracted remainder is greater than or equal to the divisor
    if (sub_remainder >= divisor_word) {
        printf("sub_remainder is greater than or equal to divisor. performing an additional shift\n");

        // Shift the dividend one more word to the right
        for (int i = dividend_top - 1; i > 0; i--) {
            shifted_dividend[i] = shifted_dividend[i - 1];
        }
        shifted_dividend[0] = 0;

        // Update the quotient
        quotient[0] = (multiplication_times << 4) | (sub_remainder / divisor_word);

        // Update the remainder
        sub_remainder = sub_remainder % divisor_word;
    } else {
        // Update the quotient
        quotient[0] = multiplication_times;
    }

    // Update the remainder
    remainder[0] = sub_remainder;

    // quotient[0] = 0x3;
    // remainder[0] = 0x4;

    printf("-- bn_div --\n");
    return 1;
}

int main()
{
    BN_ULONG dividend[WORDS] = {0, 0xb0c89}; //724105
    BN_ULONG divisor[WORDS] = {0, 0xd97}; //3479

    reverse_order(dividend);
    reverse_order(divisor);

    bn_print("dividend = ", dividend);
    bn_print("divisor = ", divisor);

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

    bn_print("quotient (d0) = ", quotient); //208
    bn_print("remainder (0x1d9) = ", remainder); //473

    return 0;
}