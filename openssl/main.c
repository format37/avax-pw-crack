#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <stdint.h>
#define PBKDF2_SHA512_STATIC
#define PBKDF2_SHA512_IMPLEMENTATION

#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>

#include <vector>
#include "nlohmann/json.hpp"
#include <fstream>
#include <signal.h>
#include <iostream>


// #define debug_print

#include "child_key.h"

// BIGNUM *r = BN_new();
// BIGNUM *a = BN_new();
// BIGNUM *b = BN_new();
// BN_CTX *ctx = BN_CTX_new();
// BN_MONT_CTX *mont = BN_MONT_CTX_new();
// // Initialize a, b, mont as needed
// BN_mod_mul_montgomery(r, a, b, mont, ctx);

#define MAX_PASSPHRASE_LENGTH 100 // TODO: Change this to the maximum passphrase length
#define P_CHAIN_ADDRESS_LENGTH 45
#define OVERFLOW_FLAG ULLONG_MAX

// Add these at the top with other defines
#define MAX_ALPHABET_LENGTH 256

// Update the find_variant_id function to take alphabet as parameter
unsigned long long find_variant_id(const char* s, const char* alphabet, int alphabet_length) {
    int base = alphabet_length;
    int length = strlen(s);
    
    unsigned long long offset = 0;
    unsigned long long value = 0;

    // Compute offsets for all shorter lengths
    for (int i = 1; i < length; i++) {
        unsigned long long count = 1;
        for (int j = 0; j < i; j++) {
            count *= base;
        }
        offset += count;
    }

    // Convert the current string to a base-N number
    for (int i = 0; i < length; i++) {
        const char* pos = strchr(alphabet, s[i]);
        if (pos != NULL) {
            int index = (int)(pos - alphabet);
            value = value * base + index;
        }
    }

    return offset + value;
}

// Update find_letter_variant to take alphabet as parameter
void find_letter_variant(unsigned long long variant_id, char* passphrase_value, const char* alphabet, int alphabet_length) {
    // Clear result
    for (int i = 0; i < MAX_PASSPHRASE_LENGTH; i++) {
        passphrase_value[i] = '\0';
    }

    // Determine length by finding which range variant_id falls into
    int length = 1;
    unsigned long long total_count = 0;
    while (true) {
        unsigned long long count = 1;
        for (int j = 0; j < length; j++) {
            count *= alphabet_length;
        }
        
        if (variant_id < total_count + count) {
            variant_id -= total_count;
            break;
        } else {
            total_count += count;
            length++;
            if (length > MAX_PASSPHRASE_LENGTH) {
                length = MAX_PASSPHRASE_LENGTH;
                break;
            }
        }
    }

    // Decode variant_id as a base-N number into 'length' characters
    unsigned long long temp = variant_id;
    for (int i = length - 1; i >= 0; i--) {
        int remainder = (int)(temp % alphabet_length);
        temp /= alphabet_length;
        passphrase_value[i] = alphabet[remainder];
        if (i == 0) break;
    }
}

void save_result(const char* address, const char* passphrase) {
    std::ofstream outfile("result.txt");
    if (outfile.is_open()) {
        outfile << "Address: " << address << std::endl;
        outfile << "Passphrase: " << passphrase << std::endl;
        outfile.close();
    }
}

// Update generate_passphrases_iterative to use the alphabet from config
void generate_passphrases_iterative(const std::string& start_passphrase, const std::string& end_passphrase, 
                                  const std::string& mnemonic, const std::string& expected_p_chain_address,
                                  const std::string& alphabet) {
    int alphabet_length = alphabet.length();
    std::vector<int> indices(MAX_PASSPHRASE_LENGTH, 0);
    std::string passphrase(MAX_PASSPHRASE_LENGTH, alphabet[0]);

    unsigned long long start_variant_id = find_variant_id(start_passphrase.c_str(), alphabet.c_str(), alphabet_length);
    unsigned long long end_variant_id = find_variant_id(end_passphrase.c_str(), alphabet.c_str(), alphabet_length);

    printf("Starting variant generation from ID %llu to %llu\n", start_variant_id, end_variant_id);
    printf("Search area: %llu\n", end_variant_id - start_variant_id + 1);

    for (unsigned long long variant_id = start_variant_id; variant_id <= end_variant_id; ++variant_id) {
        find_letter_variant(variant_id, &passphrase[0], alphabet.c_str(), alphabet_length);

        // Process the current passphrase
        unsigned char derived_key[64] = {0};
        compute_pbkdf2((uint8_t*)mnemonic.c_str(), mnemonic.length(), 
                      (uint8_t*)passphrase.c_str(), passphrase.length(), 
                      2048, 64, derived_key);
        
        BIP32Info master_key = bip32_from_seed(derived_key, sizeof(derived_key));
        
        // Rest of the key derivation and address generation code remains the same
        uint32_t index44 = 0x8000002C;
        uint32_t index9000 = 0x80002328;
        uint32_t index0Hardened = 0x80000000;
        uint32_t index0 = 0x00000000;

        initializePublicKeyCache();
        
        BIP32Info child_key_1 = GetChildKeyDerivation(master_key.master_private_key, master_key.chain_code, index44);
        BIP32Info child_key_2 = GetChildKeyDerivation(child_key_1.master_private_key, child_key_1.chain_code, index9000);
        BIP32Info child_key_3 = GetChildKeyDerivation(child_key_2.master_private_key, child_key_2.chain_code, index0Hardened);
        BIP32Info child_key_4 = GetChildKeyDerivation(child_key_3.master_private_key, child_key_3.chain_code, index0);
        BIP32Info child_key_5 = GetChildKeyDerivation(child_key_4.master_private_key, child_key_4.chain_code, index0);
        
        size_t publicKeyLen = 0;
        unsigned char *publicKeyBytes = GetPublicKey(child_key_5.master_private_key, 32, &publicKeyLen);
        char *publicKeyHex = byteArrayToHexString(publicKeyBytes, publicKeyLen);
        char *avaxp_address = childToAvaxpAddress(publicKeyHex);
        
        if (strcmp(avaxp_address, expected_p_chain_address.c_str()) == 0) {
            printf("Found matching passphrase: %s\n", passphrase.c_str());
            printf("Corresponding P-chain address: %s\n", avaxp_address);
            save_result(avaxp_address, passphrase.c_str());
            delete[] publicKeyHex;
            delete[] avaxp_address;
            delete[] publicKeyBytes;
            cleanupPublicKeyCache();
            exit(0);
        }
        
        cleanupPublicKeyCache();
        delete[] publicKeyHex;
        delete[] avaxp_address;
        delete[] publicKeyBytes;
    }
}

// Update main function to read and validate alphabet from config
int main() {
    // Read configuration from JSON file
    std::ifstream config_file("../config.json");
    if (!config_file.is_open()) {
        std::cerr << "Failed to open config.json" << std::endl;
        return -1;
    }
    
    nlohmann::json config;
    config_file >> config;
    
    std::string mnemonic = config["mnemonic"];
    std::string start_passphrase = config["start_passphrase"];
    std::string end_passphrase = config["end_passphrase"];
    std::string expected_p_chain_address = config["p_chain_address"];
    std::string alphabet = config["alphabet"];
    
    // Validate input
    if (mnemonic.empty() || start_passphrase.empty() || end_passphrase.empty() || 
        expected_p_chain_address.empty() || alphabet.empty()) {
        std::cerr << "Invalid configuration in config.json" << std::endl;
        return -1;
    }

    // Verify alphabet length doesn't exceed maximum
    if (alphabet.length() >= MAX_ALPHABET_LENGTH) {
        std::cerr << "Alphabet length exceeds maximum allowed length of " 
                  << MAX_ALPHABET_LENGTH - 1 << std::endl;
        return -1;
    }
    
    if (expected_p_chain_address.length() != P_CHAIN_ADDRESS_LENGTH) {
        std::cerr << "Invalid p_chain_address length in config.json" << std::endl;
        return -1;
    }
    
    printf("Starting P-chain address search...\n");
    printf("Mnemonic: %s\n", mnemonic.c_str());
    printf("Start passphrase: %s\n", start_passphrase.c_str());
    printf("End passphrase: %s\n", end_passphrase.c_str());
    printf("Expected P-chain address: %s\n", expected_p_chain_address.c_str());
    printf("Alphabet: %s\n", alphabet.c_str());
    printf("Alphabet length: %zu\n", alphabet.length());
    
    // Use iterative approach with the new alphabet
    generate_passphrases_iterative(start_passphrase, end_passphrase, mnemonic, 
                                 expected_p_chain_address, alphabet);
    
    printf("P-chain address not found within the given range.\n");
    return 0;
}