#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <stdint.h>
#include <stddef.h>

#define TEST_BIGNUM_WORDS 4

void print_bn(const char* label, const BIGNUM* bn) {
    char* bn_str = BN_bn2hex(bn);
    int i = 0;
    while (bn_str[i] == '0' && bn_str[i+1] != '\0') {
        i++;
    }
    printf("%s: %s\n", label, &bn_str[i]);
    OPENSSL_free(bn_str);
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

int main() {
    printf("++ Starting GCD calculation test ++\n");

    BN_CTX *ctx = BN_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Error: BN_CTX_new() failed.\n");
        return 1;
    }

    BN_ULONG test_values_a[][TEST_BIGNUM_WORDS] = {
        {0,0,0,0x3},                    // 1
        {0,0,0x123456789ABCDEFULL,0},   // 2
        {0,0,0x1FFF3ULL,0},             // 3
        {0,0,0xFEDCBA9876543210ULL,0},  // 4
        {0,0,0xFFFFFFFFFFFFFFFFULL,0x1},// 5
        {0,0,0,0x1},                    // 6
        {0,0,0x123456789ABCDEFULL,0xFEDCBA9876543210ULL} // 7
    };

    BN_ULONG test_values_b[][TEST_BIGNUM_WORDS] = {
        {0,0,0,0xb},                    // 1
        {0,0,0xFEDCBA987654321ULL,0},   // 2
        {0,0,0x2468ACEULL,0},           // 3
        {0,0,0xFEDCBA9876543210ULL,0},  // 4
        {0,0,0,0},                      // 5
        {0,0,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL}, // 6
        {0,0,0xFFFFFFFFFFFFFFFFULL,0x1}                    // 7
    };

    int sign_a[] = {0, 0, 0, 0, 0, 0, 0}; // Signs for 'a', add -1 for negative numbers as needed
    int sign_b[] = {0, 0, 0, 0, 0, 0, 0}; // Signs for 'b', add -1 for negative numbers as needed

    int num_tests = sizeof(test_values_a) / sizeof(test_values_a[0]);
    
    for (int i = 0; i < num_tests; ++i) {
        printf("\nTest %d:\n", i + 1);
        BIGNUM *a = BN_new();
        BIGNUM *b = BN_new();
        BIGNUM *gcd = BN_new();
        
        if (a == NULL || b == NULL || gcd == NULL || ctx == NULL) {
            fprintf(stderr, "Error allocating BIGNUMs or BN_CTX.\n");
            return 1;
        }

        set_bignum_words(a, test_values_a[i], TEST_BIGNUM_WORDS);
        set_bignum_words(b, test_values_b[i], TEST_BIGNUM_WORDS);

        // Set signs
        //if (sign_a[i]) BN_set_negative(a, 1);
        //if (sign_b[i]) BN_set_negative(b, 1);
        print_bn("a", a);
        print_bn("b", b);

        if (!BN_gcd(gcd, a, b, ctx)) {
            fprintf(stderr, "Error computing GCD.\n");
            ERR_print_errors_fp(stderr);
        } else {
            print_bn("gcd", gcd);
        }

        BN_free(a);
        BN_free(b);
        BN_free(gcd);
    }

    BN_CTX_free(ctx);
    printf("-- Finished GCD calculation test --\n");

    return 0;
}