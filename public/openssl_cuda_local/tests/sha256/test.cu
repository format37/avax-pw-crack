#include "bignum.h" // Big number arithmetic
#include "sha256.h" // SHA-256 hashing

__global__ void test() {
    // Convert the mnemonic and passphrase to byte arrays (or use them as-is if you can)
    // uint8_t *m_mnemonic = (unsigned char *)"sell stereo useless course suffer tribe jazz monster fresh excess wire again father film sudden pelican always room attack rubber pelican trash alone cancel";
    // uint8_t *salt = (unsigned char *)"mnemonicTESTPHRASE";
    // compute_sha256((uint8_t *) m_mnemonic, my_strlen((const char*) m_mnemonic));
    
    // init const char *publicKeyHex as 02ffe1073d08f0163434453127e81181be1d49e78e88f9d5662af55416fcec9d80
    const char *publicKeyHex = "02ffe1073d08f0163434453127e81181be1d49e78e88f9d5662af55416fcec9d80";

    int len;
    unsigned char publicKeyBytes[128];
    hexStringToByteArray(publicKeyHex, publicKeyBytes, &len);

    printf("Public Key: ");
    //print_as_hex_uint(publicKeyBytes, len);
    print_as_hex_uint(publicKeyBytes, (uint32_t) len);
    printf("Public Key Length: %d bytes\n", len);
	uint8_t sha256Hash[MY_SHA256_DIGEST_LENGTH];
    compute_sha256(publicKeyBytes, (uint32_t) len);
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