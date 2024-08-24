#include "pbkdf2.h"
#include "sha256.h"
#include "ripmd160.h"
#include "bech32.h"
#include "bip32.h"
#include "child_key.h"

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

__device__ void generate_salt(const char* prefix, const char* passphrase, char* salt, int max_salt_len) {
    int i = 0;
    int j = 0;

    // Copy prefix
    while (prefix[i] != '\0' && i < max_salt_len - 1) {
        salt[i] = prefix[i];
        i++;
    }

    // Copy passphrase
    while (passphrase[j] != '\0' && i < max_salt_len - 1) {
        salt[i] = passphrase[j];
        i++;
        j++;
    }

    // Null-terminate the salt
    salt[i] = '\0';
}

__device__ P_CHAIN_ADDRESS_STRUCT restore_p_chain_address(uint8_t *m_mnemonic, char *passphrase) {
    // printf("++ search_kernel ++\n");
    
    // printf("Mnemonic: %s\n", m_mnemonic);

    P_CHAIN_ADDRESS_STRUCT completeAddress;

    // uint8_t *salt = (unsigned char *)"mnemonicTESTPHRASE";
    // Calculate the length of the passphrase
    int passphrase_len = 0;
    while (passphrase[passphrase_len] != '\0') {
        passphrase_len++;
    }
    
    // Calculate the total length of the salt
    const char *prefix = "mnemonic";
    int prefix_len = 8; // length of "mnemonic" including null terminator
    int salt_len = prefix_len + passphrase_len; // -1 to avoid double null terminator
    
    // Allocate memory for the salt
    char *salt = (char*)malloc(salt_len);
    
    // Copy the prefix and passphrase into the salt
    for (int i = 0; i < prefix_len; i++) {
        salt[i] = prefix[i];
    }
    for (int i = 0; i < passphrase_len; i++) {
        salt[prefix_len + i] = passphrase[i];
    }
    
    // Use the salt in your further processing
    // For demonstration, let's print the salt
    // printf("Salt: %s\n", salt);
    
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
    // printf("bip39seed: ");
    // print_as_hex(bip39seed, 64);

    // Bip32FromSeed
    BIP32Info master_key = bip32_from_seed_kernel(bip39seed, 64);
    // printf("\nMaster Chain Code: ");
    // print_as_hex_char(master_key.chain_code, 32);
    // printf("\nMaster Private Key: ");
    // print_as_hex_char(master_key.master_private_key, 32);
    
    // Child key derivation
	uint32_t index44 = 0x8000002C;
	uint32_t index9000 = 0x80002328;
	uint32_t index0Hardened = 0x80000000;
	uint32_t index0 = 0x00000000;

    BIP32Info child_key;

    child_key = GetChildKeyDerivation(master_key.master_private_key, master_key.chain_code, index44, 0x00);
    // printf("[0] Child Chain Code: ");
    // print_as_hex_char(child_key.chain_code, 32);
    // printf("[0] Child Private Key: ");
    // print_as_hex_char(child_key.master_private_key, 32);

    child_key = GetChildKeyDerivation(child_key.master_private_key, child_key.chain_code, index9000, 0x00);
    // printf("[1] Child Chain Code: ");
    // print_as_hex_char(child_key.chain_code, 32);
    // printf("[1] Child Private Key: ");
    // print_as_hex_char(child_key.master_private_key, 32);

    child_key = GetChildKeyDerivation(child_key.master_private_key, child_key.chain_code, index0Hardened, 0x00);
    // printf("[2] Child Chain Code: ");
    // print_as_hex_char(child_key.chain_code, 32);
    // printf("[2] Child Private Key: ");
    // print_as_hex_char(child_key.master_private_key, 32);

    child_key = GetChildKeyDerivation(child_key.master_private_key, child_key.chain_code, index0, 0x03);
    // printf("[3] Child Chain Code: ");
    // print_as_hex_char(child_key.chain_code, 32);
    // printf("[3] Child Private Key: ");
    // print_as_hex_char(child_key.master_private_key, 32);

    child_key = GetChildKeyDerivation(child_key.master_private_key, child_key.chain_code, index0, 0x02);
    // printf("[4] Child Chain Code: ");
    // print_as_hex_char(child_key.chain_code, 32);
    // printf("[4] Child Private Key: ");
    // print_as_hex_char(child_key.master_private_key, 32);

    // Final public key derivation

    // Buffer for the public key
    unsigned char buffer[33];
    GetPublicKey(buffer, child_key.master_private_key, 0x02);

    // printf("      * [==6==] Cuda buffer: ");
    // print_as_hex(buffer, 33);
    // printf("\n");

    // Convert buffer to hex string
    char publicKeyHex[67];  // 66 characters for the hex string + 1 for null terminator
    bufferToHex(buffer, publicKeyHex);

    // printf("      * [==7==] Cuda publicKeyHex: %s\n", publicKeyHex);

    // Copy publicKeyBytes to publicKeyBytes_test
    unsigned char publicKeyBytes[33];
    for (int i = 0; i < 33; i++) {
        publicKeyBytes[i] = buffer[i];
    }

    // printf("[8] Public Key: ");
    // print_as_hex(publicKeyBytes, 33);
    // printf("\n");

    // Ensure all threads have completed their work before proceeding
    // __syncthreads(); // Don't need it for now

    // Compute SHA256
    uint8_t sha256Hash[SHA256_DIGEST_SIZE];
    compute_sha256(publicKeyBytes, 33, sha256Hash);

    // printf("SHA-256: ");
    // print_as_hex(sha256Hash, SHA256_DIGEST_SIZE);
    // printf("\n");

    // ripemd160
    unsigned char digest[RIPEMD160_DIGEST_SIZE];

    // Hash the message
    ripemd160((const uint8_t *)sha256Hash, MY_SHA256_DIGEST_LENGTH, digest);

    // Print the digest
    print_as_hex(digest, RIPEMD160_DIGEST_SIZE);

    // Bech32
    char b32Encoded[MAX_RESULT_LEN];
    Encode("avax", digest, RIPEMD160_DIGEST_LENGTH, b32Encoded);
    // printf("Encoded: %s\n", b32Encoded);

    // Create the complete P-chain address with "P-" prefix
    // char completeAddress[MAX_RESULT_LEN + 2];  // +2 for "P-" prefix
    strcpy_cuda(completeAddress.data, "P-");
    strcat_cuda(completeAddress.data, b32Encoded);

    // printf("-- search_kernel --\n");

    return completeAddress;
}