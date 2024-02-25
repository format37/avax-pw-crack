#include <stdio.h>
#include <stdbool.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>

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

    /*char* test_values_a[] = {
        "1",                       // Test case 1: Equal values
        "8",                       // Test case 2: Simple subtraction without borrowing
        "100000000",               // Test case 3: Borrowing from a single higher word
        "1000000000000",           // Test case 4: Borrowing across multiple words
        "10000000000000000",       // Test case 5: Zero high words trimmed in result
        "123456789ABCDEF0",        // Test case 6: Large number subtraction
        "0",                        // Test case 7: Underflow error
        "10000000000000001",           // Test case 8: Simple 2-word subtraction without borrowing
        "000000000000000FFFFFFFFFFFFFFFF1",           // Test case 9: Max value in lower word
        "1FFFFFFFFFFFFFFFF",           // Test case 10: Carry from lower to upper word
        "100000000FFFFFFFFFFFFFFFF",   // Test case 11: Large value spanning two words
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" // Test case 12: Max 2-word value
    };

    char* test_values_b[] = {
        "1",                       // Test case 1: Equal values
        "5",                       // Test case 2: Simple subtraction without borrowing
        "1",                       // Test case 3: Borrowing from a single higher word
        "1",                       // Test case 4: Borrowing across multiple words
        "1",                       // Test case 5: Zero high words trimmed in result
        "FEDCBA9876543210",        // Test case 6: Large number subtraction
        "1",                        // Test case 7: Underflow error
        "1",                           // Test case 8: Simple 2-word subtraction without borrowing
        "0000000000000000FFFFFFFFFFFFFFFF",            // Test case 9: Max value in lower word
        "FFFFFFFFFFFFFFFF",            // Test case 10: Carry from lower to upper word
        "FFFFFFFFFFFFFFFF",            // Test case 11: Large value spanning two words
        "1"                            // Test case 12: Max 2-word value
    };*/

    char* test_values_a[] = {
        "1", // 1: neg - neg
        "1", // 2: pos - neg
        "1", // 3: neg - pos
        "4", // 4: neg - pos
        "4", // 5: pos - neg
        "1", // 6: neg - pos
        "1",  // 7: pos - neg
        "1", // 8: Two-word positive-neg test case (low word, high word)
        "1FFFFFFFFFFFFFFFF", // 9: Two-word neg-pos overflow test case (low word, high word)
        "0", // 10: Zero - pos
        "0", // 11: Zero - neg
    };
    int multipliers_a[] = {
        1, // 1: neg
        0, // 2: pos
        1, // 3: neg
        1, // 4: neg
        0, // 5: pos
        1, // 6: neg
        0,  // 7: pos
        0, // 8: pos
        1,  // 9: neg
        0,  // 10: Zero - pos
        0,  // 11: Zero - neg
    };
    char* test_values_b[] = {
        "1", // 1: neg - neg
        "1", // 2: pos - neg
        "1", // 3: neg - pos
        "1", // 4: neg - pos
        "1", // 5: pos - neg
        "4", // 6: neg - pos
        "4", // 7: pos - neg
        "2", // 8: Two-word negative-neg test case (low word, high word)
        "1", // 9: Two-word neg-pos overflow test case (low word, high word)
        "1", // 10: Zero - pos
        "1", // 11: Zero - neg
    };
    int multipliers_b[] = {
        1, // 1: neg
        1, // 2: neg
        0, // 3: pos
        0, // 4: pos
        1, // 5: neg
        0, // 6: pos
        1,  // 7: neg
        1, // 8: neg
        0,  // 9: pos
        0,  // 10: Zero - pos
        1,  // 11: Zero - neg
    };

    
    int num_tests = sizeof(test_values_a) / sizeof(test_values_a[0]);

    for (int test = 0; test < num_tests; ++test) {
        printf("\nTest %d:\n", test + 1);
        BIGNUM *a = BN_new();
        BIGNUM *b = BN_new();
        BIGNUM *result = BN_new();

        BN_hex2bn(&a, test_values_a[test]);
        BN_hex2bn(&b, test_values_b[test]);

        // Set sign of a according to multiplier
        BN_set_negative(a, multipliers_a[test]);
        // Set sign of b according to multiplier
        BN_set_negative(b, multipliers_b[test]);

        // Print sign of a
        printf("Sign of a: %d\n", BN_is_negative(a));
        // Print sign of b
        printf("Sign of b: %d\n", BN_is_negative(b));

        // Test subtraction (a - b)
        if(!BN_sub(result, a, b)) {
            fprintf(stderr, "Subtraction failed for test case %d\\n", test + 1);
        }

        
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