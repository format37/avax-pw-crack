#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define RIPEMD160_DIGEST_LENGTH 20
#define CHECKSUM_LENGTH 6
#define CHARSET "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
#define MAX_RESULT_LEN 90
#define MAX_HRP_LEN 20
#define MAX_VALUES_LEN (MAX_HRP_LEN * 2 + 1 + RIPEMD160_DIGEST_LENGTH + CHECKSUM_LENGTH)

// ++ Bech32 Encode ++
void ConvertBytesTo5BitGroups(uint8_t *data, size_t len, uint8_t *result, size_t *result_len) {
    uint32_t buffer = 0;
    uint8_t bufferLength = 0;
    *result_len = 0;

    for(size_t i = 0; i < len; i++) {
        uint8_t b = data[i];
        buffer = (buffer << 8) | b;
        bufferLength += 8;

        while(bufferLength >= 5) {
            result[*result_len] = (buffer >> (bufferLength - 5)) & 0x1F;
            (*result_len)++;
            bufferLength -= 5;
        }
    }

    if(bufferLength > 0) {
        result[*result_len] = (buffer << (5 - bufferLength)) & 0x1F;
        (*result_len)++;
    }
}

void ExpandHrp(const char *hrp, uint8_t *ret) {
    size_t hrp_len = strlen(hrp);
    for (size_t i = 0; i < hrp_len; ++i) {
        uint8_t c = hrp[i];
        ret[i] = c >> 5;
        ret[i + hrp_len + 1] = c & 0x1F;
    }
    ret[hrp_len] = 0;
}

uint32_t PolyMod(uint8_t *values, size_t len) {
    uint32_t chk = 1;
    uint32_t generator[] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
    for (size_t i = 0; i < len; ++i) {
        uint8_t top = (chk >> 25);
        chk = (chk & 0x1ffffff) << 5 ^ values[i];
        for (int j = 0; j < 5; ++j) {
            chk ^= ((top >> j) & 1) ? generator[j] : 0;
        }
    }
    return chk;
}

void CreateChecksum(const char *hrp, uint8_t *data, size_t data_len, uint8_t *checksum) {
    size_t hrp_len = strlen(hrp);
    size_t total_len = hrp_len * 2 + 1 + data_len + CHECKSUM_LENGTH;
    uint8_t values[MAX_VALUES_LEN];
    memset(values, 0, sizeof(values));
    ExpandHrp(hrp, values);
    memcpy(values + hrp_len * 2 + 1, data, data_len);

    uint32_t polyMod = PolyMod(values, total_len) ^ 1;
    for (int i = 0; i < CHECKSUM_LENGTH; ++i) {
        checksum[i] = (polyMod >> 5 * (5 - i)) & 0x1F;
    }
}

void Encode(const char *hrp, uint8_t *data, size_t data_len, char *result) {
    uint8_t converted_data[MAX_RESULT_LEN];
    size_t converted_data_len;
    ConvertBytesTo5BitGroups(data, data_len, converted_data, &converted_data_len);

    uint8_t checksum[CHECKSUM_LENGTH];
    CreateChecksum(hrp, converted_data, converted_data_len, checksum);

    size_t hrp_len = strlen(hrp);
    size_t result_len = hrp_len + 1 + converted_data_len + CHECKSUM_LENGTH;

    strcpy(result, hrp);
    result[hrp_len] = '1';

    for (size_t i = 0; i < converted_data_len; ++i) {
        result[hrp_len + 1 + i] = CHARSET[converted_data[i]];
    }

    for (size_t i = 0; i < CHECKSUM_LENGTH; ++i) {
        result[hrp_len + 1 + converted_data_len + i] = CHARSET[checksum[i]];
    }

    result[result_len] = '\0';
}
// -- Bech32 Encode --

int main(int argc, char **argv)
{
    // Define the RIPEMD160 hash as f5f073e58eb1aacefe410fe30fb40215aa199967
    unsigned char ripemd160Hash[20] = {0xf5, 0xf0, 0x73, 0xe5, 0x8e, 0xb1, 0xaa, 0xce, 0xfe, 0x41, 0x0f, 0xe3, 0x0f, 0xb4, 0x02, 0x15, 0xaa, 0x19, 0x99, 0x67};
    // Print the RIPEMD160 hash
    printf("RIPEMD160 Hash: ");
    for(int i = 0; i < 20; ++i) {
        printf("%02x", ripemd160Hash[i]);
    }

    char b32Encoded[MAX_RESULT_LEN];
    Encode("avax", ripemd160Hash, RIPEMD160_DIGEST_LENGTH, b32Encoded);
    printf("\nBech32 Address: %s\n", b32Encoded);

    return 0;
}