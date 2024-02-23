#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#define TEST_BIGNUM_WORDS 2 // Adjust based on the highest number of words needed

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

    // Test values for 'a'
    /*BN_ULONG test_values_a[][TEST_BIGNUM_WORDS] = {
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

    // Test values for 'a' (dividends)
    BN_ULONG test_values_a[][TEST_BIGNUM_WORDS] = {
        {0x3ULL},                             // Test Case 1: Small positive number
        {0x64ULL},                            // Test Case 2: Medium positive number
        {0xFFFFFFFFFFFFFFFFULL},              // Test Case 3: Max unsigned 64-bit integer
        {0x0ULL},                             // Test Case 4: Zero
        {0x1ULL, 0x0ULL},                     // Test Case 5: Large number spanning two words
        {0x123456789ABCDEFULL},               // Test Case 6: Large positive number
        {0x1ULL, 0xFFFFFFFFFFFFFFFFULL},      // Test Case 7: Very large number just over one word size
        {0x1ULL}                              // Test Case 8: Division by zero, should return 0
    };

    // 'n' values (divisors)
    BN_ULONG test_values_n[][TEST_BIGNUM_WORDS] = {
        {0xBULL},                             // Test Case 1: Small prime number
        {0x65ULL},                            // Test Case 2: Composite number slightly larger than a
        {0x100000000ULL},                     // Test Case 3: Small power of 2 (larger than 64-bit values)
        {0x2ULL},                             // Test Case 4: Smallest even prime (edge case for even divisor)
        {0x1ULL, 0x0ULL},                     // Test Case 5: Large prime spanning two words
        {0xFEDCBA987654323ULL},               // Test Case 6: Large prime number
        {0x1ULL, 0x100000000ULL},             // Test Case 7: Larger power of 2 spanning two words
        {0x0ULL}                              // Test Case 8: Division by zero, should return 0
    };

    int sign_a[] = {0, 0, 0, 0, 0, 0, 0, 0}; // Signs for 'a', add -1 for negative numbers as needed
    int sign_n[] = {0, 0, 0, 0, 0, 0, 0, 0}; // Signs for 'b', add -1 for negative numbers as needed

    // Number of tests defined by the number of elements in test_values_a/n arrays.
    int num_tests = sizeof(test_values_a) / sizeof(test_values_a[0]);

    for (int i = 0; i < num_tests; ++i) {
        BIGNUM *quotient = BN_new();
        BIGNUM *remainder = BN_new();
        BIGNUM *a = BN_new();
        BIGNUM *n = BN_new();
        int mod = 0;

        reverse_endian((unsigned char*)test_values_a[i], TEST_BIGNUM_WORDS * sizeof(BN_ULONG));
        reverse_endian((unsigned char*)test_values_n[i], TEST_BIGNUM_WORDS * sizeof(BN_ULONG));

        BN_bin2bn((unsigned char*)test_values_a[i], TEST_BIGNUM_WORDS * sizeof(BN_ULONG), a);
        BN_bin2bn((unsigned char*)test_values_n[i], TEST_BIGNUM_WORDS * sizeof(BN_ULONG), n);

        // Set signs
        if (sign_a[i]) BN_set_negative(a, 1);
        if (sign_n[i]) BN_set_negative(n, 1);

        mod = BN_mod(remainder, a, n, ctx);

        printf("\nTest %d:\n", i + 1);
        bn_print("remainder", remainder);
        bn_print("a", a);
        bn_print("n", n);
        printf("mod: %d\n", mod);

        BN_free(a);
        BN_free(n);
    }

    BN_CTX_free(ctx);
    return 0;
}
