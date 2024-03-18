#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#define MAX_BIGNUM_WORDS 4

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
    BN_CTX *ctx = BN_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Error: BN_CTX_new() failed.\n");
        return 1;
    }

    /*// Test values for 'a'
    BN_ULONG test_values_a[][TEST_BIGNUM_WORDS] = {
        {0x3ULL},           // Test Case 1
        {0x64ULL},          // Test Case 2: 100 in decimal
        {0x1ULL},           // Test Case 3
        {0x4ULL},           // Test Case 4
        {0x100003ULL},       // Test Case 5: Simplified large number for demonstration
        {0x123456789ABCDEFULL} // Test Case 6: Large prime number
    };

    // 'n' values (ensure these are real prime numbers for valid tests, except where prime is not required)
    BN_ULONG test_values_n[][TEST_BIGNUM_WORDS] = {
        {0xBULL},           // Test Case 1: 11 in decimal
        {0x65ULL},          // Test Case 2: 101 in decimal
        {0xDULL},           // Test Case 3: 13 in decimal
        {0x8ULL},           // Test Case 4: Non-prime, to show no inverse exists
        {0x100019ULL},       // Test Case 5: Simplified large prime number for demonstration
        {0xFEDCBA987654323ULL} // Test Case 6: Large prime number
    };*/
    BN_ULONG test_values_a[][MAX_BIGNUM_WORDS] = {
        {0,0,0,0x3}, // 0
    };
    BN_ULONG test_values_n[][MAX_BIGNUM_WORDS] = {
        {0,0,0,0xB}, // 0
    };

    int sign_a[] = {0}; // Signs for 'a', add -1 for negative numbers as needed
    int sign_n[] = {0}; // Signs for 'n', add -1 for negative numbers as needed

    // Number of tests defined by the number of elements in test_values_a/n arrays.
    int num_tests = sizeof(test_values_a) / sizeof(test_values_a[0]);

    //for (int test = 0; test < num_tests; ++test) {
    for (int i = 0; i < num_tests; ++i) {
        //printf("Test %d:\n", i);
        BIGNUM *a = BN_new();
        BIGNUM *n = BN_new();
        BIGNUM *mod_inverse = NULL;

        set_bignum_words(a, test_values_a[i], MAX_BIGNUM_WORDS);
        set_bignum_words(n, test_values_n[i], MAX_BIGNUM_WORDS);

        // Set signs
        if (sign_a[i]) BN_set_negative(a, 1);
        if (sign_n[i]) BN_set_negative(n, 1);

        mod_inverse = BN_mod_inverse(NULL, a, n, ctx);

        if (mod_inverse == NULL) {
            unsigned long err_code = ERR_get_error();  // Get the error code
            if (ERR_GET_REASON(err_code) == BN_R_NO_INVERSE) {
                printf("Test %d:\n", i);
                print_bn("a", a);
                print_bn("n", n);
                printf("No modular inverse exists for the given 'a' and 'n'.\n");
            } else {
                fprintf(stderr, "Error computing modular inverse.\n");
                ERR_print_errors_fp(stderr);
            }
        } else {
            printf("Test %d:\n", i);
            print_bn("a", a);
            print_bn("n", n);
            print_bn("modular inverse", mod_inverse);
        }

        BN_free(a);
        BN_free(n);
        BN_free(mod_inverse); // mod_inverse is created by BN_mod_inverse
        break;
    }

    BN_CTX_free(ctx);
    return 0;
}