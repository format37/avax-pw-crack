#include "bignum.h" // Big number arithmetic
#include "ripmd160.h" // SHA-256 hashing

__global__ void test() {
    // const char *message = "Hello, world!";
    // 
    // define sha256Hash as a phrase
    const char *sha256Hash_char = "e4c7762afce13f2f44b69d6af33b8f12145e14291bff7e6be29f05c6015dbe5a";
    // Init sha256Hash as a uint
    // const uint8_t sha256Hash[MY_SHA256_DIGEST_LENGTH];
    unsigned char sha256Hash[MY_SHA256_DIGEST_LENGTH];
    // Fill sha256Hash with sha256Hash_char
    // for (int i = 0; i < MY_SHA256_DIGEST_LENGTH; i++) {
    //     sscanf(sha256Hash_char + 2 * i, "%02x", &sha256Hash[i]);
    // }
    int len;
    unsigned char publicKeyBytes[128];
    hexStringToByteArray(sha256Hash_char, sha256Hash, &len);

    printf("SHA256: ");
    print_as_hex_char(sha256Hash, MY_SHA256_DIGEST_LENGTH);

    // size_t message_len = strlen(sha256Hash);
    size_t message_len = MY_SHA256_DIGEST_LENGTH;
    printf("Message length: %zu\n", message_len);

    unsigned char digest[RIPEMD160_DIGEST_SIZE];

    // Hash the message
    //ripemd160_hash((const unsigned char *)sha256Hash, MY_SHA256_DIGEST_LENGTH, digest);
    ripemd160((const uint8_t *)sha256Hash, MY_SHA256_DIGEST_LENGTH, digest);

    // Print the digest
    printf("RIPEMD-160: ");
    for (int i = 0; i < RIPEMD160_DIGEST_SIZE; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
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