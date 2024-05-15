#include <stdio.h>

#define BN_ULONG unsigned long long
#define BN_ULONG_NUM_BITS 64
#define WORDS 2

void bn_print(const char *prefix, const BN_ULONG *a)
{
    printf("%s", prefix);
    for (int i = 0; i < WORDS; ++i) {
        printf("%016llX ", a[i]);
    }
    printf("\n");
}

int find_top(const BN_ULONG *a, int top)
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

int count_significant_symbols(const BN_ULONG *a)
{
    int count = 0;
    int i = WORDS - 1;

    // Skip leading zero words
    while (i >= 0 && a[i] == 0) {
        i--;
    }

    if (i < 0) {
        return 0; // All zeros
    }

    // Count significant symbols in the top non-zero word
    BN_ULONG word = a[i];
    while (word != 0) {
        word >>= 4;
        count++;
    }

    // Add the number of symbols in the remaining non-zero words
    count += i * sizeof(BN_ULONG) * 2;

    return count;
}

int bn_div(const BN_ULONG *dividend, const BN_ULONG *divisor, BN_ULONG *quotient, BN_ULONG *remainder)
{
    printf("++ bn_div ++\n");
    printf("dividend top: %d\n", find_top(dividend, WORDS));
    printf("divisor top: %d\n", find_top(divisor, WORDS));
    printf("dividend count_significant_symbols: %d\n", count_significant_symbols(dividend));
    printf("divisor count_significant_symbols: %d\n", count_significant_symbols(divisor));
    quotient[0] = 0x3;
    remainder[0] = 0x4;

    printf("-- bn_div --\n");
    return 1;
}

int main()
{
    BN_ULONG dividend[WORDS] = {0, 0xb0c89}; //724105
    BN_ULONG divisor[WORDS] = {0, 0xd97}; //3479

    bn_print("dividend = ", dividend);
    bn_print("dividend = ", divisor);

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