#include <stdio.h>
//#include <cuda_runtime.h>
#include <stdbool.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>

/*void print_bn(const char* label, const BIGNUM* bn) {
    char* bn_str = BN_bn2hex(bn);
    printf("%s: %s\n", label, bn_str);
    OPENSSL_free(bn_str);
}*/
void print_bn(const char* label, const BIGNUM* bn) {

  bool isNeg = BN_is_negative(bn);
  
  int len = BN_num_bytes(bn);
  if (len == 0) {
    printf("%s: 0\n", label);
    return; 
  }
  
  unsigned char* str = (unsigned char*)malloc(len);
  BN_bn2bin(bn, str);

  printf("%s: ", label);
  
  if (isNeg) {
    printf("-");
  }
  
  bool reachedNonZero = false;
  for(int i = 0; i < len; i++) {
    if(!reachedNonZero && str[i] == 0) continue;
    
    reachedNonZero = true;
    
    if(i == 0) {
      printf("%02x", str[i]);
    }
    else {
      printf("%02x", str[i]); 
    }
  }

  printf("\n");
  
  free(str);
}

int main() {
    BN_CTX *ctx = BN_CTX_new();
    OPENSSL_assert(ctx != NULL);

    // New test values for subtraction
    /*char* test_values_a[] = {
        "1", 
        "DEF", 
        "10000", 
        "1234567890ABCDEF", 
        "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0", 
        "FFFFFFFFFFFFFFFF",
        "1234567890ABCDEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    };

    char* test_values_b[] = {
        "0", 
        "ABC", 
        "F", 
        "1000000000000000", 
        "111111111111111100000000000000000000000000000000", 
        "FFFFFFFFFFFFFFFE",
        "10000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    };*/
    char* test_values_a[] = {
        "1",                       // Test case 1: Equal values
        "8",                       // Test case 2: Simple subtraction without borrowing
        "100000000",               // Test case 3: Borrowing from a single higher word
        "1000000000000",           // Test case 4: Borrowing across multiple words
        "10000000000000000",       // Test case 5: Zero high words trimmed in result
        "123456789ABCDEF0",        // Test case 6: Large number subtraction
        "0"                        // Test case 7: Underflow error
    };

    char* test_values_b[] = {
        "1",                       // Test case 1: Equal values
        "5",                       // Test case 2: Simple subtraction without borrowing
        "1",                       // Test case 3: Borrowing from a single higher word
        "1",                       // Test case 4: Borrowing across multiple words
        "1",                       // Test case 5: Zero high words trimmed in result
        "FEDCBA9876543210",        // Test case 6: Large number subtraction
        "1"                        // Test case 7: Underflow error
    };
    /*char* test_values_a[] = {
        "1",
        "10DEF",
        "B0C00000100001234567890ABCDEF"  
    };

    char* test_values_b[] = {
        "0",
        "8ABC", 
        "A0B000000F1000000000000000"
    };*/


    int num_tests = sizeof(test_values_a) / sizeof(test_values_a[0]);

    for (int test = 0; test < num_tests; ++test) {
        BIGNUM *a = BN_new();
        BIGNUM *b = BN_new();
        BIGNUM *result = BN_new();

        BN_hex2bn(&a, test_values_a[test]);
        BN_hex2bn(&b, test_values_b[test]);

        // Test subtraction (a - b)
        if(!BN_sub(result, a, b)) {
            fprintf(stderr, "Subtraction failed for test case %d\\n", test + 1);
        }

        printf("\nTest %d:\n", test + 1);
        print_bn("a", a);
        print_bn("b", b);
        print_bn("a - b", result);

        BN_free(a);
        BN_free(b);
        BN_free(result);
    }

    BN_CTX_free(ctx);
    return 0;
}