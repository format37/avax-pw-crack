#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#define TEST_BIGNUM_WORDS 1 // Adjust based on the highest number of words needed

void bn_print(const char* prefix, const BIGNUM* bn) {
    char *number_str = BN_bn2hex(bn);
    printf("%s %s\n", prefix, number_str);
    OPENSSL_free(number_str);
}

void reverse_endian(uint8_t* array, size_t length) {
    if (!array || length <= 1) {
        // No need to reverse if array is NULL or length is 0 or 1.
        return;
    }
    
    for (size_t i = 0; i < length / 2; ++i) {
        // Swap the bytes
        uint8_t temp = array[i];
        array[i] = array[length - 1 - i];
        array[length - 1 - i] = temp;
    }
}

int main() {
    BN_CTX *ctx = BN_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Error: BN_CTX_new() failed.\n");
        return 1;
    }

    BN_ULONG test_values_a[][TEST_BIGNUM_WORDS] = {
        {0x123456789ABCDEFULL},
        /*0x1FFF3ULL,
        0x10001ULL,
        0x10001ULL*/
    };

    BN_ULONG test_values_n[][TEST_BIGNUM_WORDS] = {
        {0xFEDCBA987654323ULL},
        /*0x100000000000003ULL,
        0x461ULL, // Replace this with the actual hex representation of the prime you want to use
        0xFFFFFFFFFFFFFFFFULL*/
    };

    int sign_a[] = {0, 0, 0, 0, 0, 0}; // Signs for 'a', add -1 for negative numbers as needed
    int sign_n[] = {0, 0, 0, 0, 0, 0}; // Signs for 'b', add -1 for negative numbers as needed

    // Number of tests defined by the number of elements in test_values_a/n arrays.
    int num_tests = sizeof(test_values_a) / sizeof(test_values_a[0]);

    //for (int test = 0; test < num_tests; ++test) {
    for (int i = 0; i < num_tests; ++i) {
        BIGNUM *a = BN_new();
        BIGNUM *n = BN_new();
        BIGNUM *mod_inverse = NULL;

        if (a == NULL || n == NULL) {
            fprintf(stderr, "Error allocating BIGNUMs.\n");
            // Cleanup before exiting
            BN_free(a);
            BN_free(n);
            BN_CTX_free(ctx);
            return 1;
        }

        reverse_endian((unsigned char*)test_values_a[i], TEST_BIGNUM_WORDS * sizeof(BN_ULONG));
        reverse_endian((unsigned char*)test_values_n[i], TEST_BIGNUM_WORDS * sizeof(BN_ULONG));

        BN_bin2bn((unsigned char*)test_values_a[i], TEST_BIGNUM_WORDS * sizeof(BN_ULONG), a);
        BN_bin2bn((unsigned char*)test_values_n[i], TEST_BIGNUM_WORDS * sizeof(BN_ULONG), n);

        // Set signs
        if (sign_a[i]) BN_set_negative(a, 1);
        if (sign_n[i]) BN_set_negative(n, 1);

        mod_inverse = BN_mod_inverse(NULL, a, n, ctx);

        if (mod_inverse == NULL) {
            unsigned long err_code = ERR_get_error();  // Get the error code
            if (ERR_GET_REASON(err_code) == BN_R_NO_INVERSE) {
                printf("Test %d:\n", i + 1);
                bn_print("a", a);
                bn_print("n", n);
                printf("No modular inverse exists for the given 'a' and 'n'.\n");
            } else {
                fprintf(stderr, "Error computing modular inverse.\n");
                ERR_print_errors_fp(stderr);
            }
        } else {
            printf("Test %d:\n", i + 1);
            bn_print("a", a);
            bn_print("n", n);
            bn_print("modular inverse", mod_inverse);
        }

        BN_free(a);
        BN_free(n);
        BN_free(mod_inverse); // mod_inverse is created by BN_mod_inverse
    }

    BN_CTX_free(ctx);
    return 0;
}