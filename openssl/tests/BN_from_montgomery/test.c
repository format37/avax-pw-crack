#include <stdio.h>
#include <openssl/bn.h>

// Helper function to print the input/output values
void print_values(const BIGNUM *ret, const BIGNUM *r, const BN_MONT_CTX *mont, const char *phase) {
    char *hex;
    
    hex = BN_bn2hex(ret);
    printf("%s bn_from_montgomery_word %s ret: %s\n", 
           phase == "input" ? ">>" : "[3]", 
           phase == "input" ? ">>" : "<<", 
           hex);
    OPENSSL_free(hex);

    hex = BN_bn2hex(r);
    printf("%s bn_from_montgomery_word %s r: %s\n", 
           phase == "input" ? ">>" : "[3]", 
           phase == "input" ? ">>" : "<<", 
           hex);
    OPENSSL_free(hex);
}

// Function to run a single test case
void run_test(const char *r_hex) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *r = BN_new();
    BIGNUM *ret = BN_new();
    BIGNUM *modulus = BN_new();
    BN_MONT_CTX *mont = BN_MONT_CTX_new();
    
    // Set up the input value r
    BN_hex2bn(&r, r_hex);
    
    // Set up the modulus
    BN_hex2bn(&modulus, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    
    // Initialize Montgomery context
    BN_MONT_CTX_set(mont, modulus, ctx);
    
    // Print input values
    // print_values(ret, r, mont, "input");
    
    // Convert from Montgomery form
    BN_from_montgomery(ret, r, mont, ctx);
    
    // Print output values
    // print_values(ret, r, mont, "output");
    
    // Cleanup
    BN_CTX_free(ctx);
    BN_free(r);
    BN_free(ret);
    BN_free(modulus);
    BN_MONT_CTX_free(mont);
    
    printf("\n***\n\n");
}

int main() {
    // Test case 1
    run_test("01000003D1");
    
    // Test case 2
    run_test("9981E643E9089F48979F48C033FD129C231E295329BC66DBD7362E5A487E2097");
    
    // Test case 3
    run_test("CF3F851FD4A582D670B6B59AAC19C1368DFC5D5D1F1DC64DB15EA6D2D3DBABE2");
    
    return 0;
}