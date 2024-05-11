#include "bignum.h" // Big number arithmetic
#include "sha256.h" // SHA-256 hashing
#include "ripmd160.h" // RIPEMD-160 hashing
#include "bech32.h" // Bech32 encoding

__global__ void test() {
    const char *publicKeyHex = "02ffe1073d08f0163434453127e81181be1d49e78e88f9d5662af55416fcec9d80";

    int len;
    unsigned char publicKeyBytes[128];
    hexStringToByteArray(publicKeyHex, publicKeyBytes, &len);

    printf("Public Key: ");
    print_as_hex_uint(publicKeyBytes, (uint32_t) len);
    
    // Compute the SHA-256 hash of the public key
	uint8_t sha256Hash[MY_SHA256_DIGEST_LENGTH];
    compute_sha256(publicKeyBytes, (uint32_t) len, sha256Hash);
    printf("SHA-256 Hash: ");
    print_as_hex_uint(sha256Hash, MY_SHA256_DIGEST_LENGTH);

    // Compute the RIPEMD160 hash of the SHA-256 hash
    unsigned char ripemd160Hash[RIPEMD160_DIGEST_SIZE];
    ripemd160((const uint8_t *)sha256Hash, MY_SHA256_DIGEST_LENGTH, ripemd160Hash);
    printf("RIPEMD-160: ");
    for (int i = 0; i < RIPEMD160_DIGEST_SIZE; i++) {
        printf("%02x", ripemd160Hash[i]);
    }
    printf("\n");

    // Encode the RIPEMD160 hash
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