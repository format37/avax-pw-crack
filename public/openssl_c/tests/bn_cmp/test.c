#include <stdio.h>
#include <openssl/bn.h>
#include <stdint.h>
#include <stddef.h>

#define TEST_BIGNUM_WORDS 2

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
    printf("++ Starting OpenSSL BN_cmp test ++\n");

    BN_ULONG test_values_a[][TEST_BIGNUM_WORDS] = {
        {0x1}, // 0
        {0x1}, // 1
        {0x0, 0x1}, // 2
        {0xFFFFFFFFFFFFFFFFULL}, // 3
        {0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL}, // 4
        {0xFFFFFFFFFFFFFFFFULL, 0x0}, // 5
        {0xFFFFFFFFFFFFFFFFULL}, // 6
        {0x1}, // 7
        {0xFFFFFFFFFFFFFFFFULL}, // 8
        {0x1}, // 9
        {0x0, 0x1}, // 10
        {0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL} // 11
    };
    BN_ULONG test_values_b[][TEST_BIGNUM_WORDS] = {
        {0x1}, // 0
        {0x0, 0x1}, // 1
        {0x1}, // 2
        {0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL}, // 3
        {0xFFFFFFFFFFFFFFFFULL, 0x0}, // 4
        {0xFFFFFFFFFFFFFFFFULL}, // 5
        {0xFFFFFFFFFFFFFFFFULL}, // 6
        {0xFFFFFFFFFFFFFFFFULL}, // 7
        {0x1}, // 8
        {0x1}, // 9 
        {0x0, 0x1}, // 10
        {0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL} // 11
    };
    
    int sign_a[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}; // Signs for 'a'
    int sign_b[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0}; // Signs for 'b'

    int num_tests = sizeof(test_values_a) / sizeof(test_values_a[0]);

    for (int i = 0; i < num_tests; ++i) {
        BIGNUM *a = BN_new();
        BIGNUM *b = BN_new();

        reverse_endian((unsigned char*)test_values_a[i], TEST_BIGNUM_WORDS * sizeof(BN_ULONG));
        reverse_endian((unsigned char*)test_values_b[i], TEST_BIGNUM_WORDS * sizeof(BN_ULONG));

        // Initialize BIGNUM a and b
        BN_bin2bn((unsigned char*)test_values_a[i], TEST_BIGNUM_WORDS * sizeof(BN_ULONG), a);
        BN_bin2bn((unsigned char*)test_values_b[i], TEST_BIGNUM_WORDS * sizeof(BN_ULONG), b);

        // Set signs
        if (sign_a[i]) BN_set_negative(a, 1);
        if (sign_b[i]) BN_set_negative(b, 1);

        //printf("\nComparing a and b:\n");
        printf("\n%d. Comparing a and b:\n", i);
        bn_print("a: ", a);
        bn_print("b: ", b);

        // Compare a and b
        int cmp_result = BN_cmp(a, b);
        printf("Result of comparison: %d\n", cmp_result);

        BN_free(a);
        BN_free(b);
    }

    printf("-- Finished OpenSSL BN_cmp test --\n");

    return 0;
}
