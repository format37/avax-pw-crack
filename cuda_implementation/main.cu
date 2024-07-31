#include <fstream>
#include <iomanip>
#include <stdio.h>
#include <cuda.h>
#include "bignum.h"
#include "pbkdf2.h"

#define TEST_BIGNUM_WORDS 4

__device__ void print_as_hex_char_tmp(unsigned char *data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// BIP32 ++
typedef struct {
    unsigned char master_private_key[32];
    unsigned char chain_code[32];
} BIP32Info;

__device__ void my_cuda_memcpy_unsigned_char_b(uint8_t *dst, const uint8_t *src, unsigned int n) {
    for (unsigned int i = 0; i < n; ++i) {
        dst[i] = src[i];
    }
}

__device__ BIP32Info bip32_from_seed_kernel(const uint8_t *seed, uint32_t seed_len) {
    printf("++ bip32_from_seed_kernel ++\n");
    printf(">> seed: ");
    print_as_hex(seed, seed_len);
    printf(">> seed_len: %d\n", seed_len);

    BIP32Info info;
	// Initialize HMAC_SHA512_CTX
    HMAC_SHA512_CTX hmac;
    
    // Compute HMAC-SHA512 with "Bitcoin seed" as the key
    hmac_sha512_init(&hmac, (const uint8_t *)"Bitcoin seed", 12);
    hmac_sha512_update(&hmac, seed, seed_len);

    // Print hmac
    // printf("# hmac: ");
    
    unsigned char hash[64];
    // clear hash
    for (int i = 0; i < 64; ++i) {
        hash[i] = 0;
    }
    hmac_sha512_final(&hmac, hash);

    // Print hash
    printf("# hash: ");
    print_as_hex(hash, 64);
    
    // Copy the first 32 bytes to master_private_key and the next 32 bytes to chain_code
    //my_cuda_memcpy_unsigned_char(info->master_private_key, hash, 32);
    //my_cuda_memcpy_unsigned_char(info->chain_code, hash + 32, 32);
	my_cuda_memcpy_unsigned_char_b(info.master_private_key, hash, 32);
	my_cuda_memcpy_unsigned_char_b(info.chain_code, hash + 32, 32);

    printf("-- bip32_from_seed_kernel --\n");
	return info;
}
// BIP32 --

__device__ void reverse_order(BIGNUM *test_values_a) {
    for (size_t j = 0; j < TEST_BIGNUM_WORDS / 2; j++) {
        BN_ULONG temp_a = test_values_a->d[j];
        test_values_a->d[j] = test_values_a->d[TEST_BIGNUM_WORDS - 1 - j];
        test_values_a->d[TEST_BIGNUM_WORDS - 1 - j] = temp_a;
    }
}

__global__ void search_kernel() {
    printf("++ search_kernel ++\n");

    // Convert the mnemonic and passphrase to byte arrays
    uint8_t *m_mnemonic = (unsigned char *)"sell stereo useless course suffer tribe jazz monster fresh excess wire again father film sudden pelican always room attack rubber pelican trash alone cancel";
    // print as hex
    print_as_hex(m_mnemonic, 156);

    uint8_t *salt = (unsigned char *)"mnemonicTESTPHRASE";
    unsigned char bip39seed[64];  // This will hold the generated seed
    // Initialize bip39seed to zeros
    for (int i = 0; i < 64; ++i) {
        bip39seed[i] = 0;
    }

    // Call pbkdf2_hmac to perform the key derivation
    compute_pbkdf2(
        (uint8_t *) m_mnemonic, 
        my_strlen((const char*) m_mnemonic), 
        (uint8_t *) salt, 
        my_strlen((const char*) salt),
	    2048, 
        64,
        bip39seed
        );
    printf("bip39seed: ");
    print_as_hex(bip39seed, 64);

    // +++ Bip32FromSeed +++
    BIP32Info master_key = bip32_from_seed_kernel(bip39seed, 64);
    printf("\nMaster Chain Code: ");
    print_as_hex_char_tmp(master_key.chain_code, 32);
    printf("\nMaster Private Key: ");
    print_as_hex_char_tmp(master_key.master_private_key, 32);
    // --- Bip32FromSeed ---

    printf("\n-- search_kernel --\n");    
}

int main() {
    
    const int THREADS_PER_BLOCK = 1;
    // const int THREADS_PER_BLOCK = 256; // A good balance between occupancy and flexibility
    
    const int NUM_BLOCKS = 1;
    // const int NUM_BLOCKS = 128; // One block per SM OK

    // Launch kernel
    search_kernel<<<NUM_BLOCKS, THREADS_PER_BLOCK>>>();

    // Check for errors
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("Error: %s\n", cudaGetErrorString(err));
        return -1;
    }

    cudaDeviceSynchronize();
    cudaDeviceReset();
    return 0;
}