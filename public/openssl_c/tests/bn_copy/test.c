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
    BN_ULONG test_values_b[][TEST_BIGNUM_WORDS] = {
        {0x0ULL},               // Test Case 1
        {0x3ULL},               // Test Case 2
        {0x32ULL},              // Test Case 3
        {0x123456789ABCDEFULL}, // Test Case 4
        {0x100003ULL, 0x123456789ABCDEFULL},            // Test Case 5
        {0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL}  // Test Case 6
    };

    int sign_b[] = {0, 0, 1, 0, 0, 1}; // Signs for 'a', add -1 for negative numbers as needed

    // Number of tests defined by the number of elements in test_values_a/n arrays.
    int num_tests = sizeof(test_values_b) / sizeof(test_values_b[0]);

    //for (int test = 0; test < num_tests; ++test) {
    for (int i = 0; i < num_tests; ++i) {
        BIGNUM *a = BN_new();
        BIGNUM *b = BN_new();

        reverse_endian((unsigned char*)test_values_b[i], TEST_BIGNUM_WORDS * sizeof(BN_ULONG));

        BN_bin2bn((unsigned char*)test_values_b[i], TEST_BIGNUM_WORDS * sizeof(BN_ULONG), b);

        // Set sign
        if (sign_b[i]) BN_set_negative(b, 1);

        BN_copy(a, b);
        
        printf("Test %d:\n", i + 1);
        bn_print("a", a);
        bn_print("b", b);

        BN_free(a);
        BN_free(b);
    }

    BN_CTX_free(ctx);
    return 0;
}