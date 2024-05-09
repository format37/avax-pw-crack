#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>

#define RIPEMD160_DIGEST_LENGTH 20
#define CHECKSUM_LENGTH 6
#define CHARSET "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

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
    /*for (int i = 0; i < CHECKSUM_LENGTH; ++i) {
        //result[hrp_len + 1 + values_len + i] = CHARSET[checksum[i]];
        result[(size_t)(hrp_len + 1 + values_len + i)] = CHARSET[checksum[i]];
    }*/
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

int main(int argc, char **argv)
{
	// Define the RIPEMD160 hash as f5f073e58eb1aacefe410fe30fb40215aa199967
    unsigned char ripemd160Hash[20] = {0xf5, 0xf0, 0x73, 0xe5, 0x8e, 0xb1, 0xaa, 0xce, 0xfe, 0x41, 0x0f, 0xe3, 0x0f, 0xb4, 0x02, 0x15, 0xaa, 0x19, 0x99, 0x67};
    // Print the RIPEMD160 hash
    printf("RIPEMD160 Hash: ");
    for(int i = 0; i < 20; ++i) {
        printf("%02x", ripemd160Hash[i]);
    }
    char *b32Encoded = Encode("avax", ripemd160Hash, RIPEMD160_DIGEST_LENGTH);
    printf("\nBech32 Address: %s\n", b32Encoded);

    return 0;
}