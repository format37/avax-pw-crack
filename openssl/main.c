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

#define MAX_PASSPHRASE_LENGTH 8 // TODO: Change this to the maximum passphrase length
#define P_CHAIN_ADDRESS_LENGTH 45
#define OVERFLOW_FLAG ULLONG_MAX

unsigned long long find_variant_id(const char* s) {
    const char* alphabet = "abcdefghijklmnopqrstuvwxyz";
    int base = strlen(alphabet);
    unsigned long long result = 0;
    unsigned long long prev_result = 0;
    
    for (int i = 0; s[i] != '\0'; i++) {
        const char* pos = strchr(alphabet, s[i]);
        if (pos != NULL) {
            int index = pos - alphabet;
            
            // Check for multiplication overflow
            if (result > ULLONG_MAX / base) {
                return OVERFLOW_FLAG;
            }
            result *= base;
            
            // Check for addition overflow
            if (result > ULLONG_MAX - (index + 1)) {
                return OVERFLOW_FLAG;
            }
            result += index + 1;
            
            // Check if the value wrapped around
            if (result < prev_result) {
                return OVERFLOW_FLAG;
            }
            
            prev_result = result;
        }
    }
    
    return result;
}

void find_letter_variant(int variant_id, char* passphrase_value) {
    // Define alphabet as a constant array
    const char alphabet[] = "abcdefghijklmnopqrstuvwxyz";
    const int alphabet_length = 26;

    // Initialize first character to null terminator, rest will be filled as needed
    passphrase_value[0] = '\0';

    // Handle the special case for variant_id == 0
    if (variant_id == 0) {
        passphrase_value[0] = alphabet[0];
        passphrase_value[1] = '\0';
        return;
    }

    int result_length = 0;
    
    // Generate the passphrase
    while (variant_id > 0 && result_length < MAX_PASSPHRASE_LENGTH - 1) {  // Leave room for null terminator
        --variant_id;  // Adjust for 0-based indexing
        passphrase_value[result_length++] = alphabet[variant_id % alphabet_length];
        variant_id /= alphabet_length;
    }
    passphrase_value[result_length] = '\0';  // Ensure null termination

    // Reverse the result in-place
    int start = 0;
    int end = result_length - 1;
    while (start < end) {
        char temp = passphrase_value[start];
        passphrase_value[start] = passphrase_value[end];
        passphrase_value[end] = temp;
        ++start;
        --end;
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

void generate_passphrases_iterative(const std::string& start_passphrase, const std::string& end_passphrase, 
                                    const std::string& mnemonic, const std::string& expected_p_chain_address) {
    const char alphabet[] = "abcdefghijklmnopqrstuvwxyz";
    int max_length = MAX_PASSPHRASE_LENGTH;
    std::vector<int> indices(max_length, 0);
    std::string passphrase(max_length, 'a');

    unsigned long long start_variant_id = find_variant_id(start_passphrase.c_str());
    unsigned long long end_variant_id = find_variant_id(end_passphrase.c_str());

    for (unsigned long long variant_id = start_variant_id; variant_id <= end_variant_id; ++variant_id) {
        find_letter_variant(variant_id, &passphrase[0]);

        // Process the current passphrase
        unsigned char derived_key[64] = {0};
        compute_pbkdf2((uint8_t*)mnemonic.c_str(), mnemonic.length(), (uint8_t*)passphrase.c_str(), passphrase.length(), 2048, 64, derived_key);
        
        // Proceed with the rest of the code as before...
        BIP32Info master_key = bip32_from_seed(derived_key, sizeof(derived_key));
        
        #ifdef debug_print
            // Print the master_key
            printf("# Master Chain Code: ");
            print_as_hex_char(master_key.chain_code, 32);
            printf("# Master Private Key: ");
            print_as_hex_char(master_key.master_private_key, 32);
        #endif
        
        uint32_t index44 = 0x8000002C;
        uint32_t index9000 = 0x80002328;
        uint32_t index0Hardened = 0x80000000;
        uint32_t index0 = 0x00000000;
        
        BIP32Info child_key_1 = GetChildKeyDerivation(master_key.master_private_key, master_key.chain_code, index44);
        BIP32Info child_key_2 = GetChildKeyDerivation(child_key_1.master_private_key, child_key_1.chain_code, index9000);
        BIP32Info child_key_3 = GetChildKeyDerivation(child_key_2.master_private_key, child_key_2.chain_code, index0Hardened);
        BIP32Info child_key_4 = GetChildKeyDerivation(child_key_3.master_private_key, child_key_3.chain_code, index0);
        BIP32Info child_key_5 = GetChildKeyDerivation(child_key_4.master_private_key, child_key_4.chain_code, index0);
        
        size_t publicKeyLen = 0;
        // unsigned char *publicKeyBytes = GetPublicKey(child_key_5.master_private_key, 32, &publicKeyLen);
        unsigned char *publicKeyBytes = getCachedPublicKey(child_key_5.master_private_key, 32, &publicKeyLen);
        char *publicKeyHex = byteArrayToHexString(publicKeyBytes, publicKeyLen);
        char *avaxp_address = childToAvaxpAddress(publicKeyHex);
        
        if (strcmp(avaxp_address, expected_p_chain_address.c_str()) == 0) {
            printf("Found matching passphrase: %s\n", passphrase.c_str());
            printf("Corresponding P-chain address: %s\n", avaxp_address);
            save_result(avaxp_address, passphrase.c_str());
            // free(publicKeyHex);
            // free(avaxp_address);
            delete[] publicKeyHex;
            delete[] avaxp_address;
            exit(0);  // Exit the program after finding the match
        }
        else {
            #ifdef debug_print
                printf("Comparison is unsuccessful\n");
                printf("Passphrase: %s\n", passphrase.c_str());
                printf("Avaxp Address: %s\n", avaxp_address);
                printf("Expected P-chain Address: %s\n", expected_p_chain_address.c_str());
            #endif
        }
        
        // free(publicKeyHex);
        // free(avaxp_address);
        delete[] publicKeyHex;
        delete[] avaxp_address;
        delete[] publicKeyBytes;
    }
}

void generate_passphrases(char *passphrase, int index, int length, const char *start_passphrase, const char *end_passphrase, 
                          const char *mnemonic, const char *expected_p_chain_address) {
    const char alphabet[] = "abcdefghijklmnopqrstuvwxyz";
    
    if (index == length) {
        // Process the current passphrase
        unsigned char derived_key[64];
        // Initialize derived_key to zeros
        for (int i = 0; i < 64; ++i) {
            derived_key[i] = 0;
        }
        compute_pbkdf2((uint8_t *)mnemonic, strlen(mnemonic), (uint8_t *)passphrase, strlen(passphrase), 2048, 64, derived_key);
        
        BIP32Info master_key = bip32_from_seed(derived_key, sizeof(derived_key));
        #ifdef debug_print
            // Print the master_key
            printf("# Master Chain Code: ");
            print_as_hex_char(master_key.chain_code, 32);
            printf("# Master Private Key: ");
            print_as_hex_char(master_key.master_private_key, 32);
        #endif
        
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
        
        if (strcmp(avaxp_address, expected_p_chain_address) == 0) {
            printf("Found matching passphrase: %s\n", passphrase);
            printf("Corresponding P-chain address: %s\n", avaxp_address);
            save_result(avaxp_address, passphrase);
            delete[] publicKeyHex;
            delete[] avaxp_address;
            delete[] publicKeyBytes;
            exit(0);  // Exit the program after finding the match
        }
        else {
            #ifdef debug_print
                printf("Comparison is unsuccessful\n");
                // Print passphrase
                printf("Passphrase: %s\n", passphrase);
                // Print avaxp_address
                printf("Avaxp Address: %s\n", avaxp_address);
                // Print expected_p_chain_address
                printf("Expected P-chain Address: %s\n", expected_p_chain_address);
            #endif
            ;
        }
        
        cleanupPublicKeyCache();
        delete[] publicKeyHex;
        delete[] avaxp_address;
        delete[] publicKeyBytes;        
        return;
    }
    
    for (int i = 0; i < 26; i++) {
        passphrase[index] = alphabet[i];
        if (index == 0 && passphrase[0] < start_passphrase[0]) continue;
        if (index == 0 && passphrase[0] > end_passphrase[0]) break;
        generate_passphrases(passphrase, index + 1, length, start_passphrase, end_passphrase, mnemonic, expected_p_chain_address);
    }
}

void signal_handler(int signal) {
    std::cerr << "Caught signal " << signal << std::endl;
    exit(signal);
}

int main() {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
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
    
    // Validate input
    if (mnemonic.empty() || start_passphrase.empty() || end_passphrase.empty() || expected_p_chain_address.empty()) {
        std::cerr << "Invalid configuration in config.json" << std::endl;
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
    
    char passphrase[MAX_PASSPHRASE_LENGTH + 1];
    memset(passphrase, 0, sizeof(passphrase));
    
    // Recursive approach
    // for (int length = 1; length <= MAX_PASSPHRASE_LENGTH; length++) {
    //     generate_passphrases(passphrase, 0, length, start_passphrase.c_str(), end_passphrase.c_str(), 
    //                          mnemonic.c_str(), expected_p_chain_address.c_str());
    // }
    // printf("Passphrase: %s\n", passphrase);

    // Iterative approach
    generate_passphrases_iterative(start_passphrase, end_passphrase, mnemonic, expected_p_chain_address);
    
    printf("P-chain address not found within the given range.\n");
    return 0;
}

int main_fixed(int argc, char **argv)
{
	if (argc != 3)
	{
		fprintf(stderr, "test <arg1> <arg2>\n");
		return 1;
	}
	// pring arg1
	printf("arg1: %s\n", argv[1]);
	// pring arg2
	printf("arg2: %s\n", argv[2]);
	unsigned char derived_key[64];  // This will hold the generated seed
    // Initialize derived_key to zeros
    for (int i = 0; i < 64; ++i) {
        derived_key[i] = 0;
    }

	printf("PBKDF2 of key:arg[1], salt:arg[2], rounds:%i, dklen:%i \n", ROUNDS, DKLEN);
	compute_pbkdf2(
		(uint8_t *) argv[1], 
		strlen(argv[1]), 
		(uint8_t *) argv[2], 
		strlen(argv[2]),
	    ROUNDS, 
		DKLEN,
		derived_key
		);
	printf("\n");
	// print derived key
	printf("Seed: ");
	print_as_hex_uint(derived_key, sizeof derived_key);
	printf("\n");

	// master key
	BIP32Info master_key = bip32_from_seed(derived_key, sizeof derived_key);
	printf("# Master Chain Code: ");
	print_as_hex_char(master_key.chain_code, 32);
	printf("# Master Private Key: ");
	print_as_hex_char(master_key.master_private_key, 32);

	// child key derivation
	uint32_t index44 = 0x8000002C;
	uint32_t index9000 = 0x80002328;
	uint32_t index0Hardened = 0x80000000;
	uint32_t index0 = 0x00000000;
	BIP32Info child_key_1 = GetChildKeyDerivation(master_key.master_private_key, master_key.chain_code, index44);
	BIP32Info child_key_2 = GetChildKeyDerivation(child_key_1.master_private_key, child_key_1.chain_code, index9000);
	BIP32Info child_key_3 = GetChildKeyDerivation(child_key_2.master_private_key, child_key_2.chain_code, index0Hardened);
	BIP32Info child_key_4 = GetChildKeyDerivation(child_key_3.master_private_key, child_key_3.chain_code, index0);
	BIP32Info child_key_5 = GetChildKeyDerivation(child_key_4.master_private_key, child_key_4.chain_code, index0);
	// print child key
	printf("Child Chain Code: ");
	print_as_hex_char(child_key_5.chain_code, 32);
	printf("Child Private Key: ");
	print_as_hex_char(child_key_5.master_private_key, 32);
	printf("Child Public Key: ");
	size_t publicKeyLen = 0;
	unsigned char *publicKeyBytes = GetPublicKey(child_key_5.master_private_key, 32, &publicKeyLen);
	print_as_hex_char(publicKeyBytes, publicKeyLen);

	char *publicKeyHex = byteArrayToHexString(publicKeyBytes, publicKeyLen);
    printf("Public Key Hex: %s\n", publicKeyHex);
	char *avaxp_address = childToAvaxpAddress(publicKeyHex);
	printf("Avaxp Address: %s\n", avaxp_address);
    delete[] publicKeyHex;
    delete[] avaxp_address;
    delete[] publicKeyBytes;
    return 0;
}