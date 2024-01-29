#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <stdint.h>
#include <stddef.h>

#define TEST_BIGNUM_WORDS 2 // Adjust based on the highest number of words needed

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

void bn_print(const char* prefix, const BIGNUM* bn) {
    char *number_str = BN_bn2hex(bn);
    printf("%s %s\n", prefix, number_str);
    OPENSSL_free(number_str);
}

int main() {
    printf("++ Starting GCD calculation test ++\n");

    BN_CTX *ctx = BN_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Error: BN_CTX_new() failed.\n");
        return 1;
    }

    /*BN_ULONG test_values_a[][TEST_BIGNUM_WORDS] = {
        {0x123456789ABCDEFULL, 0x0}, // 1
        {0x1FFF3ULL, 0x0}, // 2
        {0xFEDCBA9876543210ULL, 0x0} // 3
    };

    BN_ULONG test_values_b[][TEST_BIGNUM_WORDS] = {
        {0xFEDCBA987654321ULL, 0x0}, // 1
        {0x2468ACEULL, 0x0}, // 2
        {0xFEDCBA9876543210ULL, 0x0} // 3
    };

    int sign_a[] = {0, 0, 0}; // Signs for 'a'
    int sign_b[] = {0, 0, 0}; // Signs for 'b'*/
    BN_ULONG test_values_a[][TEST_BIGNUM_WORDS] = {
        {0x123456789ABCDEFULL, 0x0}, // Original example 1
        {0x1FFF3ULL, 0x0}, // Original example 2
        {0xFEDCBA9876543210ULL, 0x0}, // Original example 3
        {0xFFFFFFFFFFFFFFFFULL, 0x1}, // Two-word case 1: Max value + 1 (overflow into the second word)
        {0x0, 0x1}, // Two-word case 2: A larger number that occupies the second word
        {0x123456789ABCDEFULL, 0xFEDCBA9876543210ULL} // Two-word case 3: Fully make use of two words
    };

    BN_ULONG test_values_b[][TEST_BIGNUM_WORDS] = {
        {0xFEDCBA987654321ULL, 0x0}, // Original example 1
        {0x2468ACEULL, 0x0}, // Original example 2
        {0xFEDCBA9876543210ULL, 0x0}, // Original example 3
        {0x0, 0x0}, // Edge case: One of the numbers is 0
        {0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL}, // Edge case: Both numbers equal, also a two-word case
        {0xFFFFFFFFFFFFFFFFULL, 0x1} // Mixed case: Significantly different values across words
    };

    int sign_a[] = {0, 0, 0, 0, 0, 0}; // Signs for 'a', add -1 for negative numbers as needed
    int sign_b[] = {0, 0, 0, 0, 0, 0}; // Signs for 'b', add -1 for negative numbers as needed

    int num_tests = sizeof(test_values_a) / sizeof(test_values_a[0]);
    
    for (int i = 0; i < num_tests; ++i) {
        BIGNUM *a = BN_new();
        BIGNUM *b = BN_new();
        BIGNUM *gcd = BN_new();
        
        if (a == NULL || b == NULL || gcd == NULL || ctx == NULL) {
            fprintf(stderr, "Error allocating BIGNUMs or BN_CTX.\n");
            return 1;
        }

        reverse_endian((unsigned char*)test_values_a[i], TEST_BIGNUM_WORDS * sizeof(BN_ULONG));
        reverse_endian((unsigned char*)test_values_b[i], TEST_BIGNUM_WORDS * sizeof(BN_ULONG));

        BN_bin2bn((unsigned char*)test_values_a[i], TEST_BIGNUM_WORDS * sizeof(BN_ULONG), a);
        BN_bin2bn((unsigned char*)test_values_b[i], TEST_BIGNUM_WORDS * sizeof(BN_ULONG), b);

        // Set signs
        if (sign_a[i]) BN_set_negative(a, 1);
        if (sign_b[i]) BN_set_negative(b, 1);

        if (!BN_gcd(gcd, a, b, ctx)) {
            fprintf(stderr, "Error computing GCD.\n");
            ERR_print_errors_fp(stderr);
        } else {
            printf("\nTest %d:\n", i + 1);
            bn_print("a", a);
            bn_print("b", b);
            bn_print("gcd", gcd);
        }

        BN_free(a);
        BN_free(b);
        BN_free(gcd);
    }

    BN_CTX_free(ctx);
    printf("-- Finished GCD calculation test --\n");

    return 0;
}