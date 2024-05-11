#include "bech32.h"

__global__ void test() {
    // Define the RIPEMD160 hash as f5f073e58eb1aacefe410fe30fb40215aa199967
    unsigned char ripemd160Hash[20] = {0xf5, 0xf0, 0x73, 0xe5, 0x8e, 0xb1, 0xaa, 0xce, 0xfe, 0x41, 0x0f, 0xe3, 0x0f, 0xb4, 0x02, 0x15, 0xaa, 0x19, 0x99, 0x67};
    // Print the RIPEMD160 hash
    printf("\nRIPEMD160 Hash: ");
    for(int i = 0; i < 20; ++i) {
        printf("%02x", ripemd160Hash[i]);
    }
    printf("\n");
    char b32Encoded[MAX_RESULT_LEN];
    Encode("avax", ripemd160Hash, RIPEMD160_DIGEST_LENGTH, b32Encoded);
    printf("Encoded: %s\n", b32Encoded);
}

// Main function
int main() {
    test<<<1, 1>>>();
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("Error: %s\n", cudaGetErrorString(err));
        return -1;
    }
    cudaDeviceSynchronize();
    return 0;
}