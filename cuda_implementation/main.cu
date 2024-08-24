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

__device__ void strcpy_cuda(char *dest, const char *src) {
    while (*src) {
        *dest = *src;
        dest++;
        src++;
    }
    *dest = '\0';
}

__device__ void strcat_cuda(char *dest, const char *src) {
    while (*dest) dest++;
    while (*src) {
        *dest = *src;
        dest++;
        src++;
    }
    *dest = '\0';
}

__device__ void print_as_hex_char_tmp(unsigned char *data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Public key derivation ++
__device__ void derive_public_key(BIGNUM* private_key, BIGNUM* publicKey) {
	// point_mul(private_key, publicKey);
    printf("++ derive_public_key ++\n");
    bn_print(">> private: ", private_key);
    bn_print(">> public: ", publicKey);
    printf("-- derive_public_key --\n");
}
// Public key derivation --

// Child key derivation ++
__device__ BIP32Info GetChildKeyDerivation(uint8_t* key, uint8_t* chainCode, uint32_t index) {
	printf("++ GetChildKeyDerivation ++\n");
    printf(">> key: ");
    print_as_hex(key, 32);
    printf(">> chainCode: ");
    print_as_hex(chainCode, 32);
    printf(">> index: %u\n", index);
    printf("\n* step 0 index: %u\n", index);
    BIP32Info info;

    // Set info to zero
    for (int i = 0; i < 32; i++) {
        info.chain_code[i] = 0;
        info.master_private_key[i] = 0;
    }

    // Compute HMAC-SHA512
    HMAC_SHA512_CTX hmac;
    uint8_t buffer[100];
    uint8_t hash[64];

    // Fill buffer according to index
    if (index == 0) {
		printf("    * INDEX is 0\n");
        
        BIGNUM newKey;
        init_zero(&newKey);
        for (int i = 0; i < 4; ++i) {
            newKey.d[3 - i] = ((BN_ULONG)key[8*i] << 56) | 
                              ((BN_ULONG)key[8*i + 1] << 48) | 
                              ((BN_ULONG)key[8*i + 2] << 40) | 
                              ((BN_ULONG)key[8*i + 3] << 32) |
                              ((BN_ULONG)key[8*i + 4] << 24) | 
                              ((BN_ULONG)key[8*i + 5] << 16) | 
                              ((BN_ULONG)key[8*i + 6] << 8) | 
                              ((BN_ULONG)key[8*i + 7]);
        }
        printf("      * Cuda newKey:");
        bn_print("", &newKey);
        
        // Initialize constants //TODO: Move it outside of each THREAD. Call once before instead and then sync
        init_zero(&CURVE_A);
        
        // For secp256k1, CURVE_B should be initialized to 7 rather than 0
        init_zero(&CURVE_B);
        CURVE_B.d[0] = 0x7;

        BN_ULONG CURVE_GX_values[MAX_BIGNUM_SIZE] = {
            0x79BE667EF9DCBBAC,
            0x55A06295CE870B07,
            0x029BFCDB2DCE28D9,
            0x59F2815B16F81798
            };
        for (int j = 0; j < MAX_BIGNUM_SIZE; ++j) {
                CURVE_GX_d[j] = CURVE_GX_values[j];
            }

        // Generator y coordinate
        BN_ULONG CURVE_GY_values[MAX_BIGNUM_SIZE] = {
            0x483ADA7726A3C465,
            0x5DA4FBFC0E1108A8,
            0xFD17B448A6855419,
            0x9C47D08FFB10D4B8
            };
        for (int j = 0; j < MAX_BIGNUM_SIZE; ++j) {
                CURVE_GY_d[j] = CURVE_GY_values[j];
            }

        // Initialize generator
        EC_POINT G;
        init_zero(&G.x);
        init_zero(&G.y);
        for (int j = 0; j < MAX_BIGNUM_SIZE; ++j) {
                G.x.d[j] = CURVE_GX_values[j];
                G.y.d[j] = CURVE_GY_values[j];
            }
        // reverse
        reverse_order(&G.x, TEST_BIGNUM_WORDS);
        reverse_order(&G.y, TEST_BIGNUM_WORDS);
        // find top
        G.x.top = find_top(&G.x);
        G.y.top = find_top(&G.y);

        init_zero(&CURVE_P);
        // Init curve prime
        // fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
        BN_ULONG CURVE_P_values[MAX_BIGNUM_SIZE] = {
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFEFFFFFC2F,
            0,0,0,0        
            };
        for (int j = 0; j < MAX_BIGNUM_SIZE; ++j) {
                CURVE_P.d[j] = CURVE_P_values[j];
            }
        // reverse
        reverse_order(&CURVE_P, TEST_BIGNUM_WORDS);
        // find top
        CURVE_P.top = find_top(&CURVE_P);
        // TODO: Check do we need to define curves, G and do reversing
        EC_POINT publicKey = ec_point_scalar_mul(&G, &newKey, &CURVE_P, &CURVE_A);
        // print &publicKey.x
        printf("      * Cuda publicKey.x: ");
        bn_print("", &publicKey.x);
        // print &publicKey.y
        printf("      * Cuda publicKey.y: ");
        bn_print("", &publicKey.y);

        return info; // TODO: Get 03 concatenated to publicKey.x as buffer

    } else {
        buffer[0] = 0;
        my_cuda_memcpy_unsigned_char(buffer + 1, key, 32);
    }

    // Append index in big-endian format to buffer
    buffer[33] = (index >> 24) & 0xFF;
    buffer[34] = (index >> 16) & 0xFF;
    buffer[35] = (index >> 8) & 0xFF;
    buffer[36] = index & 0xFF;

	hmac_sha512_init(&hmac, chainCode, 32);
    hmac_sha512_update(&hmac, buffer, 37);  // Assuming buffer_len = 37 // TODO: Check would it be defined in "int len"? 64
    hmac_sha512_final(&hmac, hash);

	// Print the pre-HMAC values
    printf("      * Cuda Pre-HMAC variable key:");
    for (int i = 0; i < 32; i++) {
        printf("%02x", key[i]);
    }
    printf("\n");

    printf("      * Cuda Pre-HMAC Buffer:");
    for (int i = 0; i < 37; i++) { // Assuming the buffer length up to the index is 37
        printf("%02x", buffer[i]);
    }
    printf("\n");

    printf("      * Cuda Pre-HMAC Key:");
    for (int i = 0; i < 32; i++) {
        printf("%02x", chainCode[i]);
    }
    printf("\n");   

	uint32_t il[8], ir[8];
	
	// Populate il and ir from hash
	my_cuda_memcpy_uint32_t(il, (uint32_t*)hash, 8 * sizeof(uint32_t)); // Using uint32_t version for il
	my_cuda_memcpy_uint32_t(ir, (uint32_t*)(hash + 32), 8 * sizeof(uint32_t)); // Using uint32_t version for ir

    // Print the hash from 32 to 64
    printf("      * Cuda hash from 32 to 64:");
    for (int i = 32; i < 64; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    // Copy the hash (from 32 to 64) to chain_code
    my_cuda_memcpy_unsigned_char(info.chain_code, hash + 32, 32);

	// After HMAC-SHA512
	printf("      * Cuda Post-HMAC hash:");
	for (int i = 0; i < 64; i++) {
		printf("%02x", hash[i]);
	}
	printf("\n");

	printf("      * Cuda il as uint32_t: ");
	for (int i = 0; i < 8; ++i) {
		printf("%08x", il[i]);
	}
	printf("\n");

	printf("      * Cuda ir as uint32_t: ");
	for (int i = 0; i < 8; ++i) {
		printf("%08x", ir[i]);
	}
	printf("\n");

    printf("      * Cuda ir as uint64_t: ");
    uint64_t ir_64[4];
    for (int i = 0; i < 8; ++i) {
        ir_64[i] = ((uint64_t)ir[2*i] << 32) | (uint64_t)ir[2*i + 1];
    }
    for (int i = 0; i < 4; ++i) {
        printf("%016lx", ir_64[i]);
    }
    printf("\n");

	// Perform the copy
	// my_cuda_memcpy_uint32_t_to_unsigned_char(info.chain_code, ir, 32);
    // Copy ir_64 to chain_code
    for (int i = 0; i < 4; i++) {
        info.chain_code[8*i] = (ir_64[i] >> 56) & 0xFF;
        info.chain_code[8*i + 1] = (ir_64[i] >> 48) & 0xFF;
        info.chain_code[8*i + 2] = (ir_64[i] >> 40) & 0xFF;
        info.chain_code[8*i + 3] = (ir_64[i] >> 32) & 0xFF;
        info.chain_code[8*i + 4] = (ir_64[i] >> 24) & 0xFF;
        info.chain_code[8*i + 5] = (ir_64[i] >> 16) & 0xFF;
        info.chain_code[8*i + 6] = (ir_64[i] >> 8) & 0xFF;
        info.chain_code[8*i + 7] = ir_64[i] & 0xFF;
    }

	// Print individual bytes of chain_code after copying
	printf("      * Individual bytes of Cuda chain_code after copying: ");
	for (int i = 0; i < 32; ++i) {
		printf("%02x", info.chain_code[i]);
	}
	printf("\n");

	// After populating il and ir
	printf("    * il: ");
	for (int i = 0; i < 8; i++) {
		printf("%08x", il[i]);
	}
	printf("\n");
	printf("    * ir: ");
	for (int i = 0; i < 8; i++) {
		printf("%08x", ir[i]);
	}
	printf("\n");

    // ir is uint32_t[8]
    // info.chain_code is unsigned char[32]

	// Addition
	BIGNUM a;
	BIGNUM b;
	BIGNUM curveOrder;
	BIGNUM newKey;
	BIGNUM publicKey;

    init_zero(&a);
    init_zero(&b);
    init_zero(&curveOrder);
    init_zero(&newKey);
    init_zero(&publicKey);

	BN_ULONG newKey_d[8];
	// uint32_t curveOrder[8] = {0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe, 0xbaaedce6, 0xaf48a03b, 0xbfd25e8c, 0xd0364141};
	// Initialize curveOrder_d for secp256k1
	// FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    // 
    curveOrder.d[0] = 0xBFD25E8CD0364141;
    curveOrder.d[1] = 0xBAAEDCE6AF48A03B;
    curveOrder.d[2] = 0xFFFFFFFFFFFFFFFE;
    curveOrder.d[3] = 0xFFFFFFFFFFFFFFFF;
    curveOrder.neg = 0;
    curveOrder.top = 4;
    
    // hash: uint8_t[64]
    // il: uint32_t il[8]
    // a.d: is BN_ULONG
    // Initialize a from il
    for (int i = 0; i < 4; ++i) {
        a.d[3 - i] = ((BN_ULONG)il[2*i] << 32) | (BN_ULONG)il[2*i + 1];
    }
    a.neg = 0;
    a.top = 4;  // We're using 4 64-bit words
    bn_print("A: ", &a);

	// key: uint8_t*
    // b.d: BN_ULONG
    // Initialize b from key
	for (int i = 0; i < 4; ++i) {
        b.d[3 - i] = ((BN_ULONG)key[8*i] << 56) | 
                     ((BN_ULONG)key[8*i + 1] << 48) | 
                     ((BN_ULONG)key[8*i + 2] << 40) | 
                     ((BN_ULONG)key[8*i + 3] << 32) |
                     ((BN_ULONG)key[8*i + 4] << 24) | 
                     ((BN_ULONG)key[8*i + 5] << 16) | 
                     ((BN_ULONG)key[8*i + 6] << 8) | 
                     ((BN_ULONG)key[8*i + 7]);
    }
    b.neg = 0;
    b.top = 4;  // We're using 4 64-bit words
    bn_print("B: ", &b);

	// Initialize newKey_d
	for (int i = 0; i < 8; i++) newKey_d[i] = 0;
	// newKey.d = newKey_d;
    for (int j = 0; j < 8; ++j) {
        newKey.d[j] = newKey_d[j]; // TODO: Check do we need to reverse the order
    }
	newKey.neg = 0;
    newKey.top = find_top(&newKey);
    bn_print("Debug Cuda newKey (Before add): ", &newKey);
	
    bn_add(&newKey, &a, &b);

    // Print A + B
    bn_print("Debug Cuda newKey (After add): ", &newKey);

    // Print curve order
    bn_print("Debug Cuda curveOrder: ", &curveOrder);

    printf("Calling bn_mod\n");
    bn_mod(&newKey, &newKey, &curveOrder);

    bn_print("Debug Cuda newKey (After mod): ", &newKey);

    // Copy newKey to info.master_private_key
    for (int i = 0; i < 4; i++) {
        info.master_private_key[8*i] = (newKey.d[3 - i] >> 56) & 0xFF;
        info.master_private_key[8*i + 1] = (newKey.d[3 - i] >> 48) & 0xFF;
        info.master_private_key[8*i + 2] = (newKey.d[3 - i] >> 40) & 0xFF;
        info.master_private_key[8*i + 3] = (newKey.d[3 - i] >> 32) & 0xFF;
        info.master_private_key[8*i + 4] = (newKey.d[3 - i] >> 24) & 0xFF;
        info.master_private_key[8*i + 5] = (newKey.d[3 - i] >> 16) & 0xFF;
        info.master_private_key[8*i + 6] = (newKey.d[3 - i] >> 8) & 0xFF;
        info.master_private_key[8*i + 7] = newKey.d[3 - i] & 0xFF;
    }
	
    printf("\n");
    return info;
}
// Child key derivation --

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

    BIP32Info child_key;

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

    // Final public key derivation

    // Buffer for the public key
    unsigned char buffer[33];
    GetPublicKey(buffer, child_key.master_private_key, 0x02);

    printf("      * [==6==] Cuda buffer: ");
    print_as_hex(buffer, 33);
    printf("\n");

    // Convert buffer to hex string
    char publicKeyHex[67];  // 66 characters for the hex string + 1 for null terminator
    bufferToHex(buffer, publicKeyHex);

    printf("      * [==7==] Cuda publicKeyHex: %s\n", publicKeyHex);

    // Copy publicKeyBytes to publicKeyBytes_test
    unsigned char publicKeyBytes[33];
    for (int i = 0; i < 33; i++) {
        publicKeyBytes[i] = buffer[i];
    }

    printf("[8] Public Key: ");
    print_as_hex(publicKeyBytes, 33);
    printf("\n");

    // Ensure all threads have completed their work before proceeding
    // __syncthreads(); // Don't need it for now

    // Compute SHA256
    uint8_t sha256Hash[SHA256_DIGEST_SIZE];
    compute_sha256(publicKeyBytes, 33, sha256Hash);

    printf("SHA-256: ");
    print_as_hex(sha256Hash, SHA256_DIGEST_SIZE);
    printf("\n");

    // ripemd160
    unsigned char digest[RIPEMD160_DIGEST_SIZE];

    // Hash the message
    ripemd160((const uint8_t *)sha256Hash, MY_SHA256_DIGEST_LENGTH, digest);

    // Print the digest
    print_as_hex(digest, RIPEMD160_DIGEST_SIZE);

    // Bech32
    char b32Encoded[MAX_RESULT_LEN];
    Encode("avax", digest, RIPEMD160_DIGEST_LENGTH, b32Encoded);
    printf("Encoded: %s\n", b32Encoded);

    // Create the complete P-chain address with "P-" prefix
    char completeAddress[MAX_RESULT_LEN + 2];  // +2 for "P-" prefix
    strcpy_cuda(completeAddress, "P-");
    strcat_cuda(completeAddress, b32Encoded);

    printf("Restored P-chain address: %s\n", completeAddress);

    // Copy the result to the output parameter
    // strcpy_cuda(result, completeAddress);

    printf("-- search_kernel --\n");
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