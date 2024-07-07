#include <stdio.h>
// Following libraries is for test purposes only
#include <openssl/bn.h>
#include <string.h>
#include <stdlib.h>

// #define BN_ULONG unsigned long long
#define BN_ULONG_NUM_BITS 64
// Number of hexadecimal symbols in a BN_ULONG value
// Each hexadecimal symbol represents 4 bits
#define BN_ULONG_NUM_SYMBOLS BN_ULONG_NUM_BITS/4
#define MAX_BIGNUM_SIZE 9

typedef struct bignum_st {
  BN_ULONG d[MAX_BIGNUM_SIZE];
  int top;
  int dmax;
  int neg;
  int flags;
} BIGNUM_CUDA;

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

void reverse_order(BN_ULONG *test_values_a) {
    for (size_t j = 0; j < MAX_BIGNUM_SIZE / 2; j++) {
        BN_ULONG temp_a = test_values_a[j];
        test_values_a[j] = test_values_a[MAX_BIGNUM_SIZE - 1 - j];
        test_values_a[MAX_BIGNUM_SIZE - 1 - j] = temp_a;
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

int find_top(const BIGNUM_CUDA *bn, int max_words) {
    for (int i = MAX_BIGNUM_SIZE - 1; i >= 0; i--) {
        if (bn->d[i] != 0) {
            return i + 1;
        }
    }
    return 1;
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

int main()
{
    unsigned char shift_count = 100;
    
    BIGNUM_CUDA bn_dividend;
    init_zero(&bn_dividend, MAX_BIGNUM_SIZE);
    
    // Set initial and end values for dividend and divisor
    bn_dividend.d[0] = 0x3ed283a825b42270;
    bn_dividend.d[1] = 0x4784810a5f24738a;
    bn_dividend.d[2] = 0x00b98f9c393b0f2e;
    bn_dividend.d[3] = 0x482aa0a22888bfe2;
    bn_dividend.d[4] = 0x07d48f3a0e0836b6;
    bn_dividend.d[5] = 0x7f815f9a69ca3854;
    bn_dividend.d[6] = 0x70a173882ae69475;
    bn_dividend.d[7] = 0x207281887e16a058;
    bn_dividend.d[8] = 0x4f8c23302a77ff9d;

    // bn_dividend.d[0] = 0x0;
    // bn_dividend.d[1] = 0x0;
    // bn_dividend.d[2] = 0x0;
    // bn_dividend.d[3] = 0x0;
    // bn_dividend.d[4] = 0x0;
    // bn_dividend.d[5] = 0x0;
    // bn_dividend.d[6] = 0x0;
    // bn_dividend.d[7] = 0x0;
    // bn_dividend.d[8] = 0x123;

    // Reverse order of dividend and divisor because of different endianness
    reverse_order(bn_dividend.d);

    bn_print_bn("[0] Dividend: ", &bn_dividend);
    
    // shift right by 
    right_shift(&bn_dividend, shift_count * 4);
    bn_print_bn("[1] Dividend: ", &bn_dividend);

    return 0;
}