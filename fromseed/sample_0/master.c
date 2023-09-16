#include <stdio.h>
#include <string.h>
#include <openssl/hmac.h>

void print_hex(unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    // Seed in hexadecimal format
    const char *seed_hex = "23cd8f21118749c3d348e114a53b1cede7fd020bfa5f9bf67938b12d67b522aaf370480ed670a1c41aae0c0062faceb6aea0c031cc2907e8aaadd23ae8076818";
    size_t seed_len = strlen(seed_hex) / 2;
    unsigned char seed[seed_len];
    
    // Convert hex string to byte array
    for (size_t i = 0; i < seed_len; i++) {
        sscanf(seed_hex + 2 * i, "%02hhx", &seed[i]);
    }

    // HMAC-SHA512
    unsigned char hash[64];
    unsigned int len = 64;
    HMAC(EVP_sha512(), "Bitcoin seed", 12, seed, seed_len, hash, &len);

    // Split the hash into the master private key and chain code
    unsigned char master_private_key[32];
    unsigned char chain_code[32];
    memcpy(master_private_key, hash, 32);
    memcpy(chain_code, hash + 32, 32);

    // Print the master private key and chain code
    printf("Master Private Key: ");
    print_hex(master_private_key, 32);
    printf("Chain Code: ");
    print_hex(chain_code, 32);

    return 0;
}
