#include <fstream>
#include <iomanip>
#include <stdio.h>
#include <cuda.h>
#include "bignum.h"
#include "pbkdf2.h"
#include "sha256.h"
#include "ripmd160.h"
#include "bech32.h"
#include "bip32.h"
#include "child_key.h"

#define TEST_BIGNUM_WORDS 4

__device__ void print_as_hex_char_tmp(unsigned char *data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
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

    // Call pbkdf2_hmac to perform the bip39seed key derivation
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

    // Bip32FromSeed
    BIP32Info master_key = bip32_from_seed_kernel(bip39seed, 64);
    printf("\nMaster Chain Code: ");
    print_as_hex_char_tmp(master_key.chain_code, 32);
    printf("\nMaster Private Key: ");
    print_as_hex_char_tmp(master_key.master_private_key, 32);
    
    // Child key derivation
	uint32_t index44 = 0x8000002C;
	uint32_t index9000 = 0x80002328;
	uint32_t index0Hardened = 0x80000000;
	uint32_t index0 = 0x00000000;

    unsigned char debug_child = 0;
    BIP32Info child_key; 

	if (!debug_child) {
        child_key = GetChildKeyDerivation(master_key.master_private_key, master_key.chain_code, index44, 0x00);
        printf("[0] Child Chain Code: ");
        print_as_hex_char_tmp(child_key.chain_code, 32);
        printf("[0] Child Private Key: ");
        print_as_hex_char_tmp(child_key.master_private_key, 32);
        
        child_key = GetChildKeyDerivation(child_key.master_private_key, child_key.chain_code, index9000, 0x00);
        printf("[1] Child Chain Code: ");
        print_as_hex_char_tmp(child_key.chain_code, 32);
        printf("[1] Child Private Key: ");
        print_as_hex_char_tmp(child_key.master_private_key, 32);

        child_key = GetChildKeyDerivation(child_key.master_private_key, child_key.chain_code, index0Hardened, 0x00);
        printf("[2] Child Chain Code: ");
        print_as_hex_char_tmp(child_key.chain_code, 32);
        printf("[2] Child Private Key: ");
        print_as_hex_char_tmp(child_key.master_private_key, 32);

        child_key = GetChildKeyDerivation(child_key.master_private_key, child_key.chain_code, index0, 0x03);
        printf("[3] Child Chain Code: ");
        print_as_hex_char_tmp(child_key.chain_code, 32);
        printf("[3] Child Private Key: ");
        print_as_hex_char_tmp(child_key.master_private_key, 32);

        child_key = GetChildKeyDerivation(child_key.master_private_key, child_key.chain_code, index0, 0x02);
        printf("[4] Child Chain Code: ");
        print_as_hex_char_tmp(child_key.chain_code, 32);
        printf("[4] Child Private Key: ");
        print_as_hex_char_tmp(child_key.master_private_key, 32);
    }
    else 
    {
        printf("Debugging child key derivation\n");
        // Define child_key.master_private_key
        unsigned char key[32] = {
            0x26, 0x99, 0xc6, 0xb5, 0xa6, 0x37, 0x82, 0x8d,
            0x01, 0x80, 0x83, 0x2e, 0x1f, 0x11, 0x7a, 0x31,
            0x57, 0xbf, 0x0f, 0x4c, 0x1b, 0xda, 0x3c, 0xc9,
            0x42, 0xfe, 0xc4, 0xf3, 0xf9, 0x5f, 0xf4, 0x37
        };
        // child_key.master_private_key = key;
        for (int i = 0; i < 32; i++) {
            child_key.master_private_key[i] = key[i];
        }
    }
    // Final public key derivation
    // char *publicKeyHex;
    char publicKeyHex[PUBLIC_KEY_SIZE * 2 + 1];  // +1 for null terminator

    // Allocate memory for the buffer
    uint8_t buffer[33];  // 32 bytes for the public key + 1 byte for the prefix

    GetPublicKey(buffer, child_key.master_private_key, 0x02); // TODO: Enable this line and disable the following DEBUG block
    // DEBGUG ++
    // // Define buffer as 02ffe1073d08f0163434453127e81181be1d49e78e88f9d5662af55416fcec9d80
    // unsigned char buffer_values[33] = {
    //     0x02, 0xff, 0xe1, 0x07, 0x3d, 0x08, 0xf0, 0x16,
    //     0x34, 0x34, 0x45, 0x31, 0x27, 0xe8, 0x11, 0x81,
    //     0xbe, 0x1d, 0x49, 0xe7, 0x8e, 0x88, 0xf9, 0xd5,
    //     0x66, 0x2a, 0xf5, 0x54, 0x16, 0xfc, 0xec, 0x9d,
    //     0x80
    // };
    // for (int i = 0; i < 33; i++) {
    //     buffer[i] = buffer_values[i];
    // }
    // DEBGUG --

    printf("      * [==6==] Cuda buffer: ");
    for (int i = 0; i < 33; i++) {
        printf("%02x", buffer[i]);
    }
    printf("\n");

    // SHA-256
    
    // Convert to const char *publicKeyHex        
    bufferToHex(buffer, publicKeyHex);
    printf("      * [==7==] Cuda publicKeyHex: %s\n", publicKeyHex);
    
    // // // publicKeyHex = "02ffe1073d08f0163434453127e81181be1d49e78e88f9d5662af55416fcec9d80";
    unsigned char publicKeyBytes[128];
    int len = 33;
    hexStringToByteArray(publicKeyHex, publicKeyBytes, &len);
    printf("[8] Public Key: ");
    print_as_hex_uint(publicKeyBytes, len);
    
    uint8_t sha256Hash[MY_SHA256_DIGEST_LENGTH];
    compute_sha256(publicKeyBytes, (uint32_t) len, sha256Hash);
    printf("SHA-256: ");
    print_as_hex_uint(sha256Hash, MY_SHA256_DIGEST_LENGTH);

    // ripemd160

    unsigned char digest[RIPEMD160_DIGEST_SIZE];

    // Hash the message
    ripemd160((const uint8_t *)sha256Hash, MY_SHA256_DIGEST_LENGTH, digest);

    // Print the digest
    printf("RIPEMD-160: ");
    for (int i = 0; i < RIPEMD160_DIGEST_SIZE; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    // Bech32
    char b32Encoded[MAX_RESULT_LEN];
    Encode("avax", digest, RIPEMD160_DIGEST_LENGTH, b32Encoded);
    printf("Encoded: %s\n", b32Encoded);

    printf("\n-- search_kernel --\n");    
}

int main() {
    
    const int THREADS_PER_BLOCK = 1;
    // const int THREADS_PER_BLOCK = 256; // A good balance between occupancy and flexibility
    
    const int NUM_BLOCKS = 1;
    // const int NUM_BLOCKS = 2;
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