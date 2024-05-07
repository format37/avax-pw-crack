#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

#define MY_SHA256_DIGEST_LENGTH 32
#define CHARSET "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
#define CHECKSUM_LENGTH 6

// ++ Declarations ++
void print_as_hex_char(unsigned char *data, int len);
// -- Declarations --

void print_as_hex_uint(const uint8_t *data,  const uint32_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// ++ ChildToAvaxpAddress ++

// ++ Bech32 Encode ++
void ConvertBytesTo5BitGroups(uint8_t *data, size_t len, int **result, size_t *result_len) {
    int buffer = 0;
    int bufferLength = 0;
    *result_len = 0;
    *result = malloc(0);

    for(size_t i = 0; i < len; i++) {
        uint8_t b = data[i];
        buffer = (buffer << 8) | b;
        bufferLength += 8;

        while(bufferLength >= 5) {
            *result_len += 1;
            *result = realloc(*result, *result_len * sizeof(int));
            (*result)[*result_len - 1] = (buffer >> (bufferLength - 5)) & 31;
            bufferLength -= 5;
        }
    }

    if(bufferLength > 0) {
        *result_len += 1;
        *result = realloc(*result, *result_len * sizeof(int));
        (*result)[*result_len - 1] = (buffer << (5 - bufferLength)) & 31;
    }
}

void ExpandHrp(const char *hrp, int *ret) {
    size_t hrp_len = strlen(hrp);
    for (size_t i = 0; i < hrp_len; ++i) {
        int c = hrp[i];
        ret[i] = c >> 5;
        ret[i + hrp_len + 1] = c & 31;
    }
    ret[hrp_len] = 0;
}

uint32_t PolyMod(int *values, size_t len) {
    uint32_t chk = 1;
    int generator[] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
    for (size_t i = 0; i < len; ++i) {
        int v = values[i];
        //int top = chk >> 25;
        uint32_t top = chk >> 25;
        //chk = (chk & 0x1ffffff) << 5 ^ v;
        chk = (chk & 0x1ffffff) << 5 ^ (uint32_t) v;
        for (int j = 0; j < 5; ++j) {
            //chk ^= ((top >> j) & 1) ? generator[j] : 0;
            chk ^= ((top >> j) & 1) ? (uint32_t) generator[j] : 0U;
        }
    }
    return chk;
}

void CreateChecksum(const char *hrp, int *data, size_t data_len, int *checksum) {
    size_t hrp_len = strlen(hrp);
    int *values = malloc((hrp_len * 2 + 1 + data_len + CHECKSUM_LENGTH) * sizeof(int));
    ExpandHrp(hrp, values);
    memcpy(values + hrp_len * 2 + 1, data, data_len * sizeof(int));
    memset(values + hrp_len * 2 + 1 + data_len, 0, CHECKSUM_LENGTH * sizeof(int));

    //int polyMod = PolyMod(values, hrp_len * 2 + 1 + data_len + CHECKSUM_LENGTH) ^ 1;
    int polyMod=0;
    uint32_t temp = PolyMod(values, hrp_len * 2 + 1 + data_len + CHECKSUM_LENGTH);
    if (temp <= INT_MAX) {
        polyMod = temp ^ 1;
    } else {
        // Handle error
        fprintf(stderr, "Error: PolyMod value is too large to fit into an int\n");
    }
    for (int i = 0; i < CHECKSUM_LENGTH; ++i) {
        checksum[i] = (polyMod >> 5 * (5 - i)) & 31;
    }

    free(values);
}

char* Encode(const char *hrp, uint8_t *data, size_t data_len) {
    int *values, *checksum;
    size_t values_len;
    ConvertBytesTo5BitGroups(data, data_len, &values, &values_len);
    checksum = malloc(CHECKSUM_LENGTH * sizeof(int));
    CreateChecksum(hrp, values, values_len, checksum);

    size_t hrp_len = strlen(hrp);
    char *result = malloc(hrp_len + 1 + values_len + CHECKSUM_LENGTH + 1);
    strcpy(result, hrp);
    strcat(result, "1");

    for (size_t i = 0; i < values_len; ++i) {
        result[hrp_len + 1 + i] = CHARSET[values[i]];
    }

    for (size_t i = 0; i < CHECKSUM_LENGTH; ++i) {
        result[hrp_len + 1 + values_len + i] = CHARSET[checksum[i]];
    }
    result[hrp_len + 1 + values_len + CHECKSUM_LENGTH] = '\0';

    free(values);
    free(checksum);

    return result;
}
// -- Bech32 Encode --

void hexStringToByteArray(const char *hexString, unsigned char *byteArray, int *byteArrayLength) {
    *byteArrayLength = strlen(hexString) / 2;
    printf("Expected length: %d\n", *byteArrayLength);  // Debug print
    for(int i = 0; i < *byteArrayLength; ++i) {
        sscanf(hexString + 2*i, "%2hhx", byteArray + i);
    }
}

void print_as_hex_char(unsigned char *data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void compute_sha256(const uint8_t *msg, size_t mlen, uint8_t *outputHash) {
    // print mlen
    printf(" _### mlen ###_: %zu\n", mlen);
    SHA256_CTX sha;
    SHA256_Init(&sha);
    SHA256_Update(&sha, msg, mlen);
    SHA256_Final(outputHash, &sha);
}

void computeRIPEMD160(unsigned char *data, size_t len, unsigned char *hash) {
    RIPEMD160(data, len, hash);
}

// Function to convert byte array to hexadecimal string
char* byteArrayToHexString(unsigned char *byteArray, size_t byteArrayLen) {
    char *hexString = malloc(byteArrayLen * 2 + 1);  // Each byte becomes two hex characters; +1 for null-terminator
    for (size_t i = 0; i < byteArrayLen; i++) {
        sprintf(hexString + i * 2, "%02x", byteArray[i]);
    }
    hexString[byteArrayLen * 2] = '\0';  // Null-terminate the string
    return hexString;
}

char* childToAvaxpAddress(const char *publicKeyHex) {
	printf("Input Public Key Hex: %s\n", publicKeyHex);
    printf("Expected Public Key Hex Length: %zu\n", strlen(publicKeyHex));
    int len;
    unsigned char publicKeyBytes[128];
    hexStringToByteArray(publicKeyHex, publicKeyBytes, &len);
    
    printf("Public Key: ");
    //print_as_hex_uint(publicKeyBytes, len);
    print_as_hex_uint(publicKeyBytes, (uint32_t) len);
    printf("Public Key Length: %d bytes\n", len);
	uint8_t sha256Hash[MY_SHA256_DIGEST_LENGTH];
    compute_sha256(publicKeyBytes, (uint32_t) len, sha256Hash);

    printf("SHA256: ");
    print_as_hex_uint(sha256Hash, MY_SHA256_DIGEST_LENGTH);


    unsigned char ripemd160Hash[RIPEMD160_DIGEST_LENGTH];
    computeRIPEMD160(sha256Hash, MY_SHA256_DIGEST_LENGTH, ripemd160Hash);
	printf("RIPEMD160: ");
	print_as_hex_char(ripemd160Hash, RIPEMD160_DIGEST_LENGTH);

	char *b32Encoded = Encode("avax", ripemd160Hash, RIPEMD160_DIGEST_LENGTH);

    char *finalAddress = malloc(strlen(b32Encoded) + 3);
    sprintf(finalAddress, "P-%s", b32Encoded);

    free(b32Encoded);
    return finalAddress;
}
// -- ChildToAvaxpAddress --

int main(int argc, char **argv)
{
    const char *publicKeyHex = "02ffe1073d08f0163434453127e81181be1d49e78e88f9d5662af55416fcec9d80";

    printf("Public Key Hex: %s\n", publicKeyHex);
	char *avaxp_address = childToAvaxpAddress(publicKeyHex);
	printf("Avaxp Address: %s\n", avaxp_address);

    return 0;
}