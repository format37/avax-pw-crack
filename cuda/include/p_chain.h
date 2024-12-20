#include "pbkdf2.h"
#include "sha256.h"
#include "ripmd160.h"
#include "bech32.h"
#include "bip32.h"
#include "montgomery.h"
#include "point.h"
#include "public_key.h"
#include "child_key.h"

__device__ void bufferToHex(const uint8_t *buffer, char *output) {
    // Init output
    for (size_t i = 0; i < PUBLIC_KEY_SIZE * 2 + 1; i++) {
        output[i] = '\0';
        if (i > 66) {
            printf("Error: bufferToHex output buffer overflow\n");
        }
    }
    const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < PUBLIC_KEY_SIZE; i++) {
        output[i * 2] = hex_chars[buffer[i] >> 4];
        output[i * 2 + 1] = hex_chars[buffer[i] & 0xF];
    }
    output[PUBLIC_KEY_SIZE * 2] = '\0';
}

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

struct P_CHAIN_ADDRESS_STRUCT {
    char data[MAX_RESULT_LEN + 2];
};

__device__ P_CHAIN_ADDRESS_STRUCT restore_p_chain_address(uint8_t *m_mnemonic, char *passphrase) {
    P_CHAIN_ADDRESS_STRUCT completeAddress;

    // Calculate the length of the passphrase
    int passphrase_len = 0;
    while (passphrase[passphrase_len] != '\0') {
        passphrase_len++;
    }

    // Define the maximum salt length
    #define MAX_SALT_LEN 256
    char salt[MAX_SALT_LEN];

    // Copy the prefix and passphrase into the salt
    const char *prefix = "mnemonic";
    int prefix_len = 8; // length of "mnemonic"
    for (int i = 0; i < prefix_len; i++) {
        salt[i] = prefix[i];
    }
    for (int i = 0; i < passphrase_len; i++) {
        salt[prefix_len + i] = passphrase[i];
    }
    salt[prefix_len + passphrase_len] = '\0'; // Null-terminate the salt
    
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

    // Bip32FromSeed
    BIP32Info master_key = bip32_from_seed_kernel(bip39seed, 64);
    #ifdef debug_print
        printf("[0] Master private key: ");
        for (int i = 0; i < 32; i++) {
            printf("%02x", master_key.master_private_key[i]);
        }
        printf("\n");
    #endif
    

    // Child key derivation
	uint32_t index44 = 0x8000002C;
	uint32_t index9000 = 0x80002328;
	uint32_t index0Hardened = 0x80000000;
	uint32_t index0 = 0x00000000;

    BIP32Info child_key;
    child_key = GetChildKeyDerivation(master_key.master_private_key, master_key.chain_code, index44);
    child_key = GetChildKeyDerivation(child_key.master_private_key, child_key.chain_code, index9000);
    child_key = GetChildKeyDerivation(child_key.master_private_key, child_key.chain_code, index0Hardened);
    child_key = GetChildKeyDerivation(child_key.master_private_key, child_key.chain_code, index0);
    child_key = GetChildKeyDerivation(child_key.master_private_key, child_key.chain_code, index0);

    // Final public key derivation
    // Buffer for the public key
    unsigned char buffer[33];
    #ifdef debug_print
        printf("p_chain.h => GetPublicKey\n");
    #endif
    GetPublicKey(buffer, child_key.master_private_key);

    // Convert buffer to hex string
    char publicKeyHex[67];  // 66 characters for the hex string + 1 for null terminator
    bufferToHex(buffer, publicKeyHex);

    // Copy publicKeyBytes to publicKeyBytes_test
    unsigned char publicKeyBytes[33];
    for (int i = 0; i < 33; i++) {
        publicKeyBytes[i] = buffer[i];
    }

    // Compute SHA256
    uint8_t sha256Hash[SHA256_DIGEST_SIZE];
    compute_sha256(publicKeyBytes, 33, sha256Hash);

    // ripemd160
    unsigned char digest[RIPEMD160_DIGEST_SIZE];

    // Hash the message
    ripemd160((const uint8_t *)sha256Hash, MY_SHA256_DIGEST_LENGTH, digest);

    // Bech32
    char b32Encoded[MAX_RESULT_LEN];
    Encode("avax", digest, RIPEMD160_DIGEST_LENGTH, b32Encoded);

    // Create the complete P-chain address with "P-" prefix
    strcpy_cuda(completeAddress.data, "P-");
    strcat_cuda(completeAddress.data, b32Encoded);

    return completeAddress;
}