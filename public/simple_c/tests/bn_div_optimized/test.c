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

int top_word_significant_symbols(const BN_ULONG *a, const unsigned char top)
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
    printf("dividend count_significant_symbols: %d\n", top_word_significant_symbols(dividend, find_top(dividend, WORDS)));
    printf("divisor count_significant_symbols: %d\n", top_word_significant_symbols(divisor, find_top(divisor, WORDS)));
    quotient[0] = 0x3;
    remainder[0] = 0x4;

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
    if (!bn_div(dividend, divisor, quotient, remainder)) {
        printf("Error: bn_div failed\n");
        return 1;
    }

    bn_print("quotient (d0) = ", quotient); //208
    bn_print("remainder (0x1d9) = ", remainder); //473

    return 0;
}