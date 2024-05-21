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

int bn_div_0(const BN_ULONG *dividend, const BN_ULONG *divisor, BN_ULONG *quotient, BN_ULONG *remainder)
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
    shifted_dividend[dividend_top - 1] = dividend[dividend_top - 1] >> 4 * (dividend_word_top - divisor_word_top);
    bn_print("shifted_dividend = ", shifted_dividend);
    if (shifted_dividend[dividend_top - 1] < divisor[divisor_top - 1]) {
        printf("dividend >> 4 is less than divisor. performing an additional shift\n"); // TODO: check the word edge case
        shifted_dividend[dividend_top - 1] = dividend[dividend_top - 1] >> 4 * (dividend_word_top - divisor_word_top - 1);
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

    // Step 4: Assign the next sign of the dividend to the remainder
    printf("\n# 4. Assign the next sign of the dividend to the remainder\n");
    printf("attention_sign = %d\n", attention_sign);
    for (int i = 0; i < WORDS; i++) {
        shifted_dividend[i] = dividend[i];
    }
    shifted_dividend_word = shifted_dividend[dividend_top - 1];
    printf("shifted_dividend_word (B0C89) = %016llX\n", shifted_dividend_word);

    // Extract the next sign from the shifted dividend word
    unsigned char shift_value = attention_sign - 1;
    BN_ULONG next_sign = shifted_dividend_word >> (4 * shift_value) & 0xF; // TODO: Was tested on a edge case. Need to check with the larger values
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
    printf("multiplication_times = %016llX\n", multiplication_times);
    printf("shift_value = %d\n", shift_value);
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

int bn_div_1(const BN_ULONG *dividend, const BN_ULONG *divisor, BN_ULONG *quotient, BN_ULONG *remainder)
{
    printf("++ bn_div ++\n");
    unsigned char dividend_top = find_top(dividend, WORDS);
    unsigned char divisor_top = find_top(divisor, WORDS);
    unsigned char dividend_word_top = top_word_significant_symbols(dividend, dividend_top);
    unsigned char divisor_word_top = top_word_significant_symbols(divisor, divisor_top);

    BN_ULONG divisor_word = divisor[divisor_top - 1];

    unsigned char attention_sign = dividend_word_top;

    BN_ULONG shifted_dividend[WORDS];
    for (int i = 0; i < WORDS; i++) {
        shifted_dividend[i] = dividend[i];
    }
    
    for (int i = 0; i < WORDS; i++) {
        quotient[i] = 0;
        remainder[i] = 0;
    }

    while (attention_sign > 1) {
        unsigned char extension_shift = 0;
        printf("\n# 1. Shift the dividend %d times to the right\n", dividend_word_top - divisor_word_top);
        attention_sign = dividend_word_top - divisor_word_top;
        shifted_dividend[dividend_top - 1] = dividend[dividend_top - 1] >> 4 * (dividend_word_top - divisor_word_top);
        bn_print("shifted_dividend = ", shifted_dividend);
        
        if (shifted_dividend[dividend_top - 1] < divisor[divisor_top - 1]) {
            printf("dividend >> 4 is less than divisor. performing an additional shift\n");
            shifted_dividend[dividend_top - 1] = dividend[dividend_top - 1] >> 4 * (dividend_word_top - divisor_word_top - 1);
            attention_sign -= 1;
            extension_shift += 1;
        }
        bn_print("shifted_dividend = ", shifted_dividend);

        printf("\n# 2. %016llX * %016llX\n", shifted_dividend[dividend_top - 1], divisor_word);
        BN_ULONG shifted_dividend_word = shifted_dividend[dividend_top - 1];
        BN_ULONG multiplied_quotient = divisor_word;
        unsigned char multiplication_times = 1;
        while (multiplied_quotient < shifted_dividend_word) {
            multiplied_quotient += divisor_word;
            multiplication_times++;
        }
        if (multiplied_quotient > shifted_dividend_word) {
            multiplied_quotient -= divisor_word;
            multiplication_times--;
        }
        printf("multiplication_times = %016llX\n", multiplication_times);
        printf("multiplied_quotient = %016llX\n", multiplied_quotient);

        printf("\n# 3. %016llX - %016llX\n", shifted_dividend_word, multiplied_quotient);
        BN_ULONG sub_remainder = shifted_dividend_word - multiplied_quotient;
        printf("sub_remainder = %016llX\n", sub_remainder);

        printf("\n# 4. Assign the next sign of the dividend to the remainder\n");
        printf("attention_sign = %d\n", attention_sign);
        for (int i = 0; i < WORDS; i++) {
            shifted_dividend[i] = dividend[i];
        }
        shifted_dividend_word = shifted_dividend[dividend_top - 1];
        printf("shifted_dividend_word = %016llX\n", shifted_dividend_word);

        unsigned char shift_value = attention_sign - 1;
        BN_ULONG next_sign = shifted_dividend_word >> (4 * shift_value) & 0xF;
        printf("next_sign = %X\n", next_sign);

        sub_remainder <<= 4;
        sub_remainder |= next_sign;
        printf("sub_remainder with next sign = %016llX\n", sub_remainder);

        printf("\n# 5. Shift and assign the multiplication_times to the quotient\n");
        quotient[dividend_top - 1] |= multiplication_times << (4 * extension_shift);
        printf("multiplication_times = %016llX\n", multiplication_times);
        printf("extension_shift = %d\n", extension_shift);
        bn_print("quotient = ", quotient);

        printf("\n# 6. Assign the sub_remainder to the remainder\n");
        remainder[dividend_top - 1] = sub_remainder;
        printf("remainder[dividend_top-1] = %016llX\n", sub_remainder);
        printf("attention_sign = %d\n", attention_sign);

        dividend_word_top--;
    }

    printf("\n-- bn_div --\n");
    return 1;
}

int bn_div_2(const BN_ULONG *dividend, const BN_ULONG *divisor, BN_ULONG *quotient, BN_ULONG *remainder)
{
    printf("++ bn_div ++\n");
    unsigned char dividend_words = find_top(dividend, WORDS);
    unsigned char divisor_words = find_top(divisor, WORDS);
    unsigned char dividend_significant_symbols = top_word_significant_symbols(dividend, dividend_words);
    unsigned char divisor_significant_symbols = top_word_significant_symbols(divisor, divisor_words);

    BN_ULONG divisor_top_word = divisor[divisor_words - 1];

    unsigned char symbols_to_process = dividend_significant_symbols;

    BN_ULONG shifted_dividend[WORDS];
    for (int i = 0; i < WORDS; i++) {
        shifted_dividend[i] = dividend[i];
    }
    
    for (int i = 0; i < WORDS; i++) {
        quotient[i] = 0;
        remainder[i] = 0;
    }

    symbols_to_process = dividend_significant_symbols - divisor_significant_symbols;

    while (symbols_to_process > 1) {
        printf("\n\n### symbols_to_process = %d\n", symbols_to_process);
        unsigned char additional_shift = 0;
        printf("\n# 1. Shift the dividend %d times to the right\n", dividend_significant_symbols - divisor_significant_symbols);
        // symbols_to_process = dividend_significant_symbols - divisor_significant_symbols;
        shifted_dividend[dividend_words - 1] = dividend[dividend_words - 1] >> 4 * (dividend_significant_symbols - divisor_significant_symbols);
        bn_print("shifted_dividend = ", shifted_dividend);
        symbols_to_process -= 1;
        printf("symbols_to_process = %d\n", symbols_to_process);
        
        if (shifted_dividend[dividend_words - 1] < divisor[divisor_words - 1]) {
            printf("dividend >> 4 is less than divisor. performing an additional shift\n");
            shifted_dividend[dividend_words - 1] = dividend[dividend_words - 1] >> 4 * (dividend_significant_symbols - divisor_significant_symbols - 1);
            symbols_to_process -= 1;
            printf("symbols_to_process = %d\n", symbols_to_process);
            additional_shift += 1;
        }
        bn_print("shifted_dividend = ", shifted_dividend);

        printf("\n# 2. %016llX * %016llX\n", shifted_dividend[dividend_words - 1], divisor_top_word);
        BN_ULONG dividend_top_word = shifted_dividend[dividend_words - 1];
        BN_ULONG multiplied_divisor = divisor_top_word;
        unsigned char quotient_digit = 1;
        while (multiplied_divisor < dividend_top_word) {
            multiplied_divisor += divisor_top_word;
            quotient_digit++;
        }
        if (multiplied_divisor > dividend_top_word) {
            multiplied_divisor -= divisor_top_word;
            quotient_digit--;
        }
        printf("quotient_digit = %016llX\n", quotient_digit);
        printf("multiplied_divisor = %016llX\n", multiplied_divisor);

        printf("\n# 3. %016llX - %016llX\n", dividend_top_word, multiplied_divisor);
        BN_ULONG subtraction_result = dividend_top_word - multiplied_divisor;
        printf("subtraction_result = %016llX\n", subtraction_result);

        printf("\n# 4. Assign the next symbol of the dividend to the remainder\n");
        printf("symbols_to_process = %d\n", symbols_to_process);
        for (int i = 0; i < WORDS; i++) {
            shifted_dividend[i] = dividend[i];
        }
        dividend_top_word = shifted_dividend[dividend_words - 1];
        printf("dividend_top_word = %016llX\n", dividend_top_word);

        unsigned char shift_value = symbols_to_process - 1;
        BN_ULONG next_symbol = dividend_top_word >> (4 * shift_value) & 0xF;
        printf("next_symbol = %X\n", next_symbol);

        subtraction_result <<= 4;
        subtraction_result |= next_symbol;
        printf("subtraction_result with next symbol = %016llX\n", subtraction_result);

        printf("\n# 5. Shift and assign the quotient_digit to the quotient\n");
        quotient[dividend_words - 1] |= quotient_digit << (4 * additional_shift);
        printf("quotient_digit = %016llX\n", quotient_digit);
        printf("additional_shift = %d\n", additional_shift);
        bn_print("quotient = ", quotient);

        printf("\n# 6. Assign the subtraction_result to the remainder\n");
        remainder[dividend_words - 1] = subtraction_result; // TODO: Do we replace the remainder or add to it?
        printf("remainder[dividend_words-1] = %016llX\n", subtraction_result);
        printf("symbols_to_process = %d\n", symbols_to_process);

        dividend_significant_symbols--;
    }

    printf("\n-- bn_div --\n");
    return 1;
}

unsigned int get_value_from_to(const BN_ULONG a, const unsigned char from, const unsigned char to)
{
    // get_value_from_to(0xb0c89, 0, 4);  // 0x0C89
    return (a >> (4 * from)) & ((1 << (4 * (to - from))) - 1);
}

int bn_div_3(const BN_ULONG *dividend, const BN_ULONG *divisor, BN_ULONG *quotient, BN_ULONG *remainder)
{
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

    unsigned char symbols_to_process = dividend_significant_symbols;

    BN_ULONG shifted_dividend[WORDS];
    for (int i = 0; i < WORDS; i++) {
        shifted_dividend[i] = dividend[i];
    }

    symbols_to_process = dividend_significant_symbols;
    unsigned char start_symbol = dividend_significant_symbols - divisor_significant_symbols;
    unsigned char end_symbol = dividend_significant_symbols;

    printf("\n# 0. getting shift from %d to %d of the dividend\n", start_symbol, end_symbol);
    shifted_dividend[dividend_words - 1] = get_value_from_to(dividend[dividend_words - 1], start_symbol, end_symbol);
    
    BN_ULONG subtraction_result = 0;

    while (start_symbol > 0) {
        printf("\n###\n");
        printf("start_symbol = %d\n", start_symbol);
        printf("end_symbol = %d\n", end_symbol);
        
        bn_print("shifted_dividend = ", shifted_dividend); // OK

        if (shifted_dividend[dividend_words - 1] < divisor[divisor_words - 1]) {
            printf("\n# 1. shifted_dividend is less than %016llX. performing an additional shift\n", divisor[divisor_words - 1]);
            if (start_symbol == 0) {
                printf("a. Error: start_symbol is 0\n"); // TODO: implement the case when start_symbol is 0
                return 0;
            }
            start_symbol -= 1;
            printf("start_symbol = %d\n", start_symbol);
            printf("end_symbol = %d\n", end_symbol);
            // shifted_dividend[dividend_words - 1] = get_value_from_to(dividend[dividend_words - 1], start_symbol, end_symbol);
            // Instead of shift, we need to shift left on 1 and set start_symbol from dividend
            BN_ULONG next_symbol = dividend[dividend_words - 1] >> (4 * start_symbol) & 0xF;
            printf("next_symbol = %X\n", next_symbol);
            shifted_dividend[dividend_words - 1] <<= 4;
            shifted_dividend[dividend_words - 1] |= next_symbol;
            bn_print("shifted_dividend = ", shifted_dividend);
        }
        

        printf("\n# 2. divisor_multiplicator * %016llX < %016llX\n", divisor_top_word, shifted_dividend[dividend_words - 1]);
        BN_ULONG dividend_top_word = shifted_dividend[dividend_words - 1];
        BN_ULONG multiplied_divisor = divisor_top_word;
        unsigned char divisor_multiplicator = 1;
        while (multiplied_divisor < dividend_top_word) {
            multiplied_divisor += divisor_top_word;
            divisor_multiplicator++;
        }
        if (multiplied_divisor > dividend_top_word) {
            multiplied_divisor -= divisor_top_word;
            divisor_multiplicator--;
        }
        printf("divisor_multiplicator = %016llX\n", divisor_multiplicator);

        printf("\n# 2b assign the divisor_multiplicator to the quotient\n");
        quotient[dividend_words - 1] |= divisor_multiplicator << (4 * start_symbol);
        printf("quotient[dividend_words - 1] = %016llX\n", quotient[dividend_words - 1]);

        printf("\nmultiplied_divisor = %016llX\n", multiplied_divisor);

        printf("\n# 3. %016llX - %016llX\n", dividend_top_word, multiplied_divisor);
        subtraction_result = dividend_top_word - multiplied_divisor;
        printf("subtraction_result = %016llX\n", subtraction_result);

        printf("\n# 4. Assign the next symbol of the dividend to the remainder\n");
        // printf("symbols_to_process = %d\n", symbols_to_process);
        for (int i = 0; i < WORDS; i++) {
            shifted_dividend[i] = dividend[i];
        }
        dividend_top_word = shifted_dividend[dividend_words - 1];
        printf("dividend_top_word = %016llX\n", dividend_top_word);

        // unsigned char shift_value = symbols_to_process - 1;
        if (start_symbol == 0) {
            // printf("b. Error: start_symbol is 0\n"); // TODO: implement the case when start_symbol is 0
            // return 0;
            // unsigned char shift_value = start_symbol - 1;
            break;
        }
        
        start_symbol -= 1;
        printf("start_symbol = %d\n", start_symbol);
        // BN_ULONG next_symbol = dividend_top_word >> (4 * shift_value) & 0xF;
        BN_ULONG next_symbol = dividend_top_word >> (4 * start_symbol) & 0xF;
        printf("next_symbol = %X\n", next_symbol);
        
        subtraction_result <<= 4;
        subtraction_result |= next_symbol;
        printf("subtraction_result with next symbol = %016llX\n", subtraction_result);
        shifted_dividend[dividend_words - 1] = subtraction_result;  
              

        // if (start_symbol == 0) {
        //     printf("c. Error: start_symbol is 0\n"); // TODO: implement the case when start_symbol is 0
        //     return 0;
        // }
        // start_symbol -= 1;
        // printf("start_symbol = %d\n", start_symbol);
    }

    printf("\n# final: assign the subtraction_result to the remainder\n");
    remainder[dividend_words - 1] = subtraction_result;

    printf("\n-- bn_div --\n");
    return 1;
}

int main()
{
    //BN_ULONG dividend[WORDS] = {0, 0xb0c89}; //724105
    BN_ULONG dividend[WORDS] = {0, 0xb0c893};
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
    if (!bn_div_3(dividend, divisor, quotient, remainder)) {
        printf("Error: bn_div failed\n");
        return 1;
    }

    bn_print("quotient (d0) = ", quotient); //208
    bn_print("remainder (0x1d9) = ", remainder); //473

    return 0;
}