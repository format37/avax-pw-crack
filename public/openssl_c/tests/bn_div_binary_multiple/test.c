#include <stdio.h>
#include <stdint.h>
#include <string.h> // For memset
#define BN_ULONG uint64_t
#define BN_ULONG_NUM_BITS (sizeof(BN_ULONG) * 8)
#define WORDS 4 // Define the number of words as a constant

void convert_to_binary_array(BN_ULONG value[], int binary[], int words) {
    for (int word = 0; word < words; ++word) {
        for (int i = 0; i < BN_ULONG_NUM_BITS; ++i) {
            binary[word * BN_ULONG_NUM_BITS + i] = (value[word] >> (BN_ULONG_NUM_BITS - 1 - i)) & 1;
        }
    }
}

void convert_back_to_bn_ulong(int binary[], BN_ULONG value[], int words) {
    for (int word = 0; word < words; ++word) {
        value[word] = 0;
        for (int i = 0; i < BN_ULONG_NUM_BITS; ++i) {
            value[word] |= ((BN_ULONG)binary[word * BN_ULONG_NUM_BITS + i] << (BN_ULONG_NUM_BITS - 1 - i));
        }
    }
    printf("convert_back_to_bn_ulong value: %p words: %d\n", value, words);
}

// ... (binary_division should be adapted to handle multiple-word operands)
// Updated binary_division function would be implemented similarly to the single-word version,
// but it needs to manage a longer arrays for the dividend, divisor, quotient, and remainder.

// To reduce complexity and length, we will not show the full function here, but it would be analogous
// to the single-word division function with appropriately extended arrays and additional handling
// for the multiple-word looping.

void binary_division(int dividend[], int divisor[], int quotient[], int remainder[], int words) {
    int total_bits = words * BN_ULONG_NUM_BITS;
    // Init temp with zeros
    int temp[total_bits];
    memset(temp, 0, sizeof(temp));
    
    for (int i = 0; i < total_bits; ++i) {
        // Shift temp left by 1
        for (int j = 0; j < total_bits - 1; ++j) {
            temp[j] = temp[j+1];
        }
        temp[total_bits - 1] = dividend[i];
        
        // Check if temp is greater than or equal to divisor
        int can_subtract = 1;
        for (int j = 0; j < total_bits; ++j) {
            if (temp[j] != divisor[j]) {
                can_subtract = temp[j] > divisor[j];
                break;
            }
        }

        // Subtract divisor from temp if temp >= divisor
        if(can_subtract) {
            quotient[i] = 1;
            for (int j = total_bits - 1; j >= 0; --j) {
                temp[j] -= divisor[j];
                if (temp[j] < 0) {  // Borrow from the next bit if needed
                    temp[j] += 2;
                    temp[j-1] -= 1;
                }
            }
        } else {
            quotient[i] = 0;
        }
    }

    // Remainder is in temp after division
    memcpy(remainder, temp, total_bits * sizeof(int));
}

void binary_mul(int a[], int b[], int result[], int words) {
    int total_bits = words * BN_ULONG_NUM_BITS;
    // Init result with zeros
    memset(result, 0, total_bits * sizeof(int));
    for (int i = 0; i < total_bits; ++i) {
        if (b[i]) {
            int carry = 0;
            for (int j = total_bits - 1; j >= 0; --j) {
                int sum = result[j] + a[j - i + total_bits - 1] + carry;
                result[j] = sum & 1;
                carry = sum >> 1;
            }
        }
    }
}

void binary_add(int a[], int b[], int result[], int words) {
    int total_bits = words * BN_ULONG_NUM_BITS;
    // Init result with zeros
    memset(result, 0, total_bits * sizeof(int));

    int carry = 0;
    for (int i = total_bits - 1; i >= 0; --i) {
        result[i] = a[i] + b[i] + carry;
        if (result[i] > 1) {
            result[i] -= 2;
            carry = 1;
        } else {
            carry = 0;
        }
    }
}

int main() {
    // Print BN_ULONG_NUM_BITS using %zu for size_t
    printf("BN_ULONG_NUM_BITS: %zu\n", BN_ULONG_NUM_BITS);

    // If you also want to print the size of BN_ULONG, you can do it like this:
    printf("Size of BN_ULONG: %zu bytes\n", sizeof(BN_ULONG));
    //BN_ULONG B[WORDS] = {0xFEDCBA0987654321, 0xFEDCBA0987654321}; // Example values for B
    //BN_ULONG A[WORDS] = {0x6, 0x0}; // Example values for B

    //BN_ULONG A[WORDS] = {0x1234567890ABCDEF, 0x1234567890ABCDEF}; // Example values for A    
    //BN_ULONG B[WORDS] = {0x2, 0}; // Example values for B

    BN_ULONG A[WORDS] = {0, 0, 0x1, 0x0000000000000005}; // Example values for A is B
    BN_ULONG B[WORDS] = {0, 0, 0, 0x2}; // Example values for B is 3

    int binary_A[WORDS * BN_ULONG_NUM_BITS];
    int binary_B[WORDS * BN_ULONG_NUM_BITS];
    int binary_quotient[WORDS * BN_ULONG_NUM_BITS];
    int binary_remainder[WORDS * BN_ULONG_NUM_BITS];

    memset(binary_quotient, 0, sizeof(binary_quotient)); // Zero-initialize the array
    memset(binary_remainder, 0, sizeof(binary_remainder)); // Zero-initialize the array

    convert_to_binary_array(A, binary_A, WORDS);
    convert_to_binary_array(B, binary_B, WORDS);

    // Print the binary arrays
    printf("\nBinary dividend: ");
    for (int i = 0; i < WORDS * BN_ULONG_NUM_BITS; ++i) {
        printf("%d", binary_A[i]);
    }
    printf("\nBinary divisor: ");
    for (int i = 0; i < WORDS * BN_ULONG_NUM_BITS; ++i) {
        printf("%d", binary_B[i]);
    }
    printf("\n");
    
    binary_division(binary_A, binary_B, binary_quotient, binary_remainder, WORDS);

    // Print the binary arrays
    printf("\nBinary quotient: ");
    for (int i = 0; i < WORDS * BN_ULONG_NUM_BITS; ++i) {
        printf("%d", binary_quotient[i]);
    }
    printf("\nBinary remainder: ");
    for (int i = 0; i < WORDS * BN_ULONG_NUM_BITS; ++i) {
        printf("%d", binary_remainder[i]);
    }
    printf("\n");

    BN_ULONG quotient[WORDS];
    BN_ULONG remainder[WORDS];

    convert_back_to_bn_ulong(binary_quotient, quotient, WORDS);
    convert_back_to_bn_ulong(binary_remainder, remainder, WORDS);

    printf("A: ");
    for (int i = 0; i < WORDS; ++i) {
        printf("%lX", A[i]);
    }
    printf("\nB: ");
    for (int i = 0; i < WORDS; ++i) {
        printf("%lX", B[i]);
    }
    printf("\nQuotient: ");
    for (int i = 0; i < WORDS; ++i) {
        printf("%lX", quotient[i]);
    }
    printf("\nRemainder: ");
    for (int i = 0; i < WORDS; ++i) {
        printf("%lX", remainder[i]);
    }
    printf("\n");

    printf("Multiplication\n");
    printf("A: ");
    for (int i = 0; i < WORDS; ++i) {
        printf("%lX", A[i]);
    }
    printf("\nB: ");
    for (int i = 0; i < WORDS; ++i) {
        printf("%lX", B[i]);
    }
    printf("\n");
    int binary_result[WORDS * BN_ULONG_NUM_BITS];
    binary_mul(binary_A, binary_B, binary_result, WORDS);
    BN_ULONG result[WORDS];
    convert_back_to_bn_ulong(binary_result, result, WORDS);
    printf("Result: ");
    for (int i = 0; i < WORDS; ++i) {
        printf("%lX", result[i]);
    }
    printf("\n");

    printf("Addition\n");
    printf("A: ");
    for (int i = 0; i < WORDS; ++i) {
        printf("%lX", A[i]);
    }
    printf("\nB: ");
    for (int i = 0; i < WORDS; ++i) {
        printf("%lX", B[i]);
    }
    printf("\n");
    int binary_sum[WORDS * BN_ULONG_NUM_BITS];
    binary_add(binary_A, binary_B, binary_sum, WORDS);
    BN_ULONG sum[WORDS];
    convert_back_to_bn_ulong(binary_sum, sum, WORDS);
    printf("Sum: ");
    for (int i = 0; i < WORDS; ++i) {
        printf("%lX", sum[i]);
    }
    printf("\n");

    return 0;
}