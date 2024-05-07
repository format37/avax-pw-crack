#include "bignum.h" // Big number arithmetic
#include "sha256.h" // SHA-256 hashing

__global__ void test() {
    // Convert the mnemonic and passphrase to byte arrays (or use them as-is if you can)
    uint8_t *m_mnemonic = (unsigned char *)"sell stereo useless course suffer tribe jazz monster fresh excess wire again father film sudden pelican always room attack rubber pelican trash alone cancel";
    uint8_t *salt = (unsigned char *)"mnemonicTESTPHRASE";
    compute_sha256((uint8_t *) m_mnemonic, my_strlen((const char*) m_mnemonic));
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