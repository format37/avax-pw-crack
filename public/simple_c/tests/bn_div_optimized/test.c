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
    // This function is using the long division algorithm on big numbers
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

    unsigned char attention_sign = dividend_word_top;

    // Step 1: Shift the dividend dividend_word_top - divisor_word_top times to the right
    printf("\n# 1. Shift the dividend %d times to the right\n", dividend_word_top - divisor_word_top);
    attention_sign = dividend_word_top - divisor_word_top;
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
    // unsigned char multiplicator_shift = 0;
    if (shifted_dividend[dividend_top - 1] < divisor[divisor_top - 1]) {
        printf("dividend >> 4 is less than divisor. performing an additional shift\n"); // TODO: check the word edge case
        shifted_dividend[dividend_top - 1] = dividend[dividend_top - 1] >> 4 * (dividend_word_top - divisor_word_top - 1);
        // multiplicator_shift += 1;
        attention_sign -= 1;
    }
    bn_print("shifted_dividend = ", shifted_dividend);
    
    // Step 2: Multiplication of the shifted dividend by the divisor
    printf("\n# 2. %016llX * %016llX\n", shifted_dividend[dividend_top - 1], divisor_word);
    // unsigned long long shifted_quotient;
    BN_ULONG shifted_remainder;
    // shifted_quotient = shifted_dividend[dividend_top - 1] / shifted_divisor[divisor_top - 1];
    // shifted_remainder = shifted_dividend[dividend_top - 1] % shifted_divisor[divisor_top - 1];
    // Classic division and modulo is not available for big numbers. Therefore we use the addiction and comparison
    BN_ULONG shifted_dividend_word = shifted_dividend[dividend_top - 1];
    BN_ULONG multiplied_quotient = divisor_word;
    // Shift the multiplied_quotient multiplicator_shift times to the left
    // multiplied_quotient <<= 4 * multiplicator_s hift;

    unsigned char multiplication_times = 1;
    while (multiplied_quotient < shifted_dividend_word) {
        multiplied_quotient += divisor_word;
        multiplication_times++;
    }
    if (multiplied_quotient > shifted_dividend_word) {
        multiplied_quotient -= divisor_word;
        multiplication_times--;
    }
    // Shift the multiplication_times to the left
    // multiplication_times <<= 4 * multiplicator_shift;
    printf("multiplication_times = %016llX\n", multiplication_times);
    printf("multiplied_quotient = %016llX\n", multiplied_quotient);

    // Step 3: Subtraction of the multiplied divisor from the shifted dividend
    printf("\n# 3. %016llX - %016llX\n", shifted_dividend_word, multiplied_quotient);
    BN_ULONG sub_remainder = shifted_dividend_word - multiplied_quotient;
    printf("sub_remainder = %016llX\n", sub_remainder);

    // // Step 4: Assign the next sign of the dividend to the remainder
    // printf("\n# 4. Assign the next sign of the dividend to the remainder\n");
    // for (int i = 0; i < WORDS; i++) {
    //     shifted_dividend[i] = dividend[i];
    // }
    // shifted_dividend_word = shifted_dividend[dividend_top - 1];
    // // print as hex, (void*)shifted_dividend_word
    // printf("shifted_dividend_word (B0C89)= %016llX\n", shifted_dividend_word);
    // // Extract 9 from B0C89 (next sign)
    // // Shift sub_remainder left and add 9 to the remainder

    // Step 4: Assign the next sign of the dividend to the remainder
    printf("\n# 4. Assign the next sign of the dividend to the remainder\n");
    printf("attention_sign = %d\n", attention_sign);
    for (int i = 0; i < WORDS; i++) {
        shifted_dividend[i] = dividend[i];
    }
    shifted_dividend_word = shifted_dividend[dividend_top - 1];
    printf("shifted_dividend_word (B0C89) = %016llX\n", shifted_dividend_word);

    // Extract the next sign from the shifted dividend word
    // unsigned char next_sign = (shifted_dividend_word >> 4 * (dividend_word_top - divisor_word_top - 1)) & 0xF; // 8
    unsigned char shift_value = attention_sign - 1;
    // BN_ULONG next_sign = shifted_dividend_word << (4 * shift_value) & 0xF << (4 * shift_value);
    // next_sign >>= 4 * shift_value;
    BN_ULONG next_sign = shifted_dividend_word >> (4 * shift_value) & 0xF; // TODO: Was tested on a edge case. Need to check with the larger values
    // unsigned char next_sign = (shifted_dividend_word >> (4 * (dividend_word_top - 1))) & 0xF; // B
    printf("next_sign (9) = %X\n", next_sign);

    // Shift the sub_remainder to the left by 4 bits (1 hexadecimal digit)
    sub_remainder <<= 4;

    // Add the next sign to the sub_remainder
    sub_remainder |= next_sign;
    printf("sub_remainder with next sign = %016llX\n", sub_remainder);

    // Step 5: Shift and assign the multiplication_times to the quotient
    printf("\n# 5. Shift and assign the multiplication_times to the quotient\n");
    for (int i = 0; i < WORDS; i++) {
        quotient[i] = 0;
    }
    quotient[dividend_top - 1] = multiplication_times << 4;
    bn_print("quotient = ", quotient);

    // Step 6: Assign the sub_remainder to the remainder
    printf("\n# 6. Assign the sub_remainder to the remainder\n");
    for (int i = 0; i < WORDS; i++) {
        remainder[i] = 0;
    }
    remainder[dividend_top - 1] = sub_remainder;

    printf("\n-- bn_div --\n");
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