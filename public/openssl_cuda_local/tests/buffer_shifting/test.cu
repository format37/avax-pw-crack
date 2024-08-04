//bn_div_test.cu
#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"

#define TEST_BIGNUM_WORDS 4

__device__ void reverse_order(BN_ULONG test_values_a[][TEST_BIGNUM_WORDS], BN_ULONG test_values_b[][TEST_BIGNUM_WORDS], size_t num_rows) {
    for (size_t i = 0; i < num_rows; i++) {
        for (size_t j = 0; j < TEST_BIGNUM_WORDS / 2; j++) {
            BN_ULONG temp_a = test_values_a[i][j];
            test_values_a[i][j] = test_values_a[i][TEST_BIGNUM_WORDS - 1 - j];
            test_values_a[i][TEST_BIGNUM_WORDS - 1 - j] = temp_a;

            BN_ULONG temp_b = test_values_b[i][j];
            test_values_b[i][j] = test_values_b[i][TEST_BIGNUM_WORDS - 1 - j];
            test_values_b[i][TEST_BIGNUM_WORDS - 1 - j] = temp_b;
        }
    }
}

__global__ void testKernel() {

    uint8_t buffer[100];
    // Set buffer to 
    //  eacfd75e9a9861f1994e664fd81604470d5dc01edcd9a1fa1c975aadafbadbcb
    //03eacfd75e9a9861f1994e664fd81604470d5dc01edcd9a1fa1c975aadafbadbcb
    buffer[0] = 0xea;
    buffer[1] = 0xcf;
    buffer[2] = 0xd7;
    buffer[3] = 0x5e;
    buffer[4] = 0x9a;
    buffer[5] = 0x98;
    buffer[6] = 0x61;
    buffer[7] = 0xf1;
    buffer[8] = 0x99;
    buffer[9] = 0x4e;
    buffer[10] = 0x66;
    buffer[11] = 0x4f;
    buffer[12] = 0xd8;
    buffer[13] = 0x16;
    buffer[14] = 0x04;
    buffer[15] = 0x47;
    buffer[16] = 0x0d;
    buffer[17] = 0x5d;
    buffer[18] = 0xc0;
    buffer[19] = 0x1e;
    buffer[20] = 0xdc;
    buffer[21] = 0xd9;
    buffer[22] = 0xa1;
    buffer[23] = 0xfa;
    buffer[24] = 0x1c;
    buffer[25] = 0x97;
    buffer[26] = 0x5a;
    buffer[27] = 0xad;
    buffer[28] = 0xaf;
    buffer[29] = 0xba;
    buffer[30] = 0xdb;
    buffer[31] = 0xcb;
    printf("      * [0] Cuda Buffer after public key copy: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", buffer[i]);
    }
    printf("\n");

    // Shift the buffer by 1 byte
    for (int i = 33; i > 0; i--) {
        buffer[i] = buffer[i - 1];
    }
    // Add 03 before the buffer
    buffer[0] = 0x03;
    // Print buffer value after adding 0x03
    printf("      * [1] Cuda Buffer after adding 0x03:");
    for (int i = 0; i < 33; i++) {
        printf("%02x", buffer[i]);
    }
    printf("\n");

}

// Main function
int main() {
    testKernel<<<1, 1>>>();
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("Error: %s\n", cudaGetErrorString(err));
        return -1;
    }
    cudaDeviceSynchronize();
    return 0;
}