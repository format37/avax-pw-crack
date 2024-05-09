#include <openssl/ripemd.h>

#define MY_SHA256_DIGEST_LENGTH 32

void print_as_hex_char(unsigned char *data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void computeRIPEMD160(unsigned char *data, size_t len, unsigned char *hash) {
    RIPEMD160(data, len, hash);
}

int main(int argc, char **argv)
{

    // define sha256Hash as a phrase
    const char *sha256Hash_char = "e4c7762afce13f2f44b69d6af33b8f12145e14291bff7e6be29f05c6015dbe5a";
    // Init sha256Hash as a uint
    const uint8_t sha256Hash[MY_SHA256_DIGEST_LENGTH];
    // Fill sha256Hash with sha256Hash_char
    for (int i = 0; i < MY_SHA256_DIGEST_LENGTH; i++) {
        sscanf(sha256Hash_char + 2 * i, "%02x", &sha256Hash[i]);
    }

    printf("SHA256: ");
    print_as_hex_char(sha256Hash, MY_SHA256_DIGEST_LENGTH);

    unsigned char ripemd160Hash[RIPEMD160_DIGEST_LENGTH];
    computeRIPEMD160(sha256Hash, MY_SHA256_DIGEST_LENGTH, ripemd160Hash);
	printf("RIPEMD160: ");
	print_as_hex_char(ripemd160Hash, RIPEMD160_DIGEST_LENGTH);

    return 0;
}