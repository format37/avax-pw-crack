#include <stdio.h>
#include <stdint.h>
#include <string.h> // For memset
#define BN_ULONG uint64_t
#define BN_ULONG_NUM_BITS (sizeof(BN_ULONG) * 8)
#define WORDS 2 // Define the number of words as a constant

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

int main() {
    BN_ULONG A[WORDS] = {0x1234567890ABCDEF, 0x1234567890ABCDEF}; // Example values for A
    //BN_ULONG B[WORDS] = {0xFEDCBA0987654321, 0xFEDCBA0987654321}; // Example values for B
    //BN_ULONG A[WORDS] = {0x6, 0x0}; // Example values for B
    BN_ULONG B[WORDS] = {0, 0x2}; // Example values for B

    int binary_A[WORDS * BN_ULONG_NUM_BITS];
    int binary_B[WORDS * BN_ULONG_NUM_BITS];
    int binary_quotient[WORDS * BN_ULONG_NUM_BITS];
    int binary_remainder[WORDS * BN_ULONG_NUM_BITS];

    memset(binary_quotient, 0, sizeof(binary_quotient)); // Zero-initialize the array
    memset(binary_remainder, 0, sizeof(binary_remainder)); // Zero-initialize the array

    convert_to_binary_array(A, binary_A, WORDS);
    convert_to_binary_array(B, binary_B, WORDS);
    
    binary_division(binary_A, binary_B, binary_quotient, binary_remainder, WORDS);

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

    return 0;
}