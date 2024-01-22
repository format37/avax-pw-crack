#include <stdio.h>
#include <stdint.h>

#define BN_ULONG uint64_t
#define BN_ULONG_NUM_BITS (sizeof(BN_ULONG) * 8)

void convert_to_binary(BN_ULONG value, int binary[BN_ULONG_NUM_BITS]) {
    for (int i = 0; i < BN_ULONG_NUM_BITS; ++i) {
        binary[i] = (value >> (BN_ULONG_NUM_BITS - 1 - i)) & 1;
    }
}

BN_ULONG convert_to_BN_ULONG(int binary[BN_ULONG_NUM_BITS]) {
    BN_ULONG value = 0;
    for (int i = 0; i < BN_ULONG_NUM_BITS; ++i) {
        value |= ((BN_ULONG)binary[i] << (BN_ULONG_NUM_BITS - 1 - i));
    }
    return value;
}

void binary_division(int dividend[BN_ULONG_NUM_BITS], int divisor[BN_ULONG_NUM_BITS], 
                     int quotient[BN_ULONG_NUM_BITS], int remainder[BN_ULONG_NUM_BITS]) {
    int temp[BN_ULONG_NUM_BITS] = {0};
    
    for (int i = 0; i < BN_ULONG_NUM_BITS; ++i) {
        // Shift left by 1
        for (int j = 0; j < BN_ULONG_NUM_BITS - 1; ++j) {
            temp[j] = temp[j+1];
        }
        temp[BN_ULONG_NUM_BITS - 1] = dividend[i];
        
        // Subtract divisor from temp if temp >= divisor
        int can_subtract = 1;
        for (int j = 0; j < BN_ULONG_NUM_BITS; ++j) {
            if (temp[j] < divisor[j]) {
                can_subtract = 0;
                break;
            } else if (temp[j] > divisor[j]) {
                break;
            }
        }
        
        if(can_subtract) {
            quotient[i] = 1;
            for (int j = 0; j < BN_ULONG_NUM_BITS; ++j) {
                temp[j] = temp[j] - divisor[j] + (temp[j] < divisor[j] ? 1 : 0);  // Borrow
            }
        } else {
            quotient[i] = 0;
        }
    }
    
    // Remainder is in temp after division
    for (int i = 0; i < BN_ULONG_NUM_BITS; ++i) {
        remainder[i] = temp[i];
    }
}

int main() {
    //BN_ULONG A = 0x1234567890ABCDEF; // Example values for A
    //BN_ULONG B = 0xFEDCBA0987654321; // Example values for B
    BN_ULONG A = 0x6; // Example values for A
    BN_ULONG B = 0x4; // Example values for B

    int binary_A[BN_ULONG_NUM_BITS];
    int binary_B[BN_ULONG_NUM_BITS];
    int binary_quotient[BN_ULONG_NUM_BITS] = {0};
    int binary_remainder[BN_ULONG_NUM_BITS] = {0};

    convert_to_binary(A, binary_A);
    convert_to_binary(B, binary_B);
    binary_division(binary_A, binary_B, binary_quotient, binary_remainder);

    BN_ULONG quotient = convert_to_BN_ULONG(binary_quotient);
    BN_ULONG remainder = convert_to_BN_ULONG(binary_remainder);

    printf("A: 0x%llX\n", A); // Using llX to print 64-bit number in hex
    printf("B: 0x%llX\n", B);
    printf("Quotient: 0x%llX\n", quotient);
    printf("Remainder: 0x%llX\n", remainder);

    return 0;
}