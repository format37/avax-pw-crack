#include <gmp.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#define MY_SHA256_DIGEST_LENGTH 32
#define RIPEMD160_DIGEST_SIZE 20

typedef struct {
    mpz_t state[5];
    unsigned char buffer[64];
    size_t buffer_size;
    mpz_t length;
} RIPEMD160_CTX;

void print_as_hex_char(unsigned char *data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void ripemd160_init(RIPEMD160_CTX *ctx) {
    mpz_init_set_str(ctx->state[0], "67452301", 16);
    mpz_init_set_str(ctx->state[1], "EFCDAB89", 16);
    mpz_init_set_str(ctx->state[2], "98BADCFE", 16);
    mpz_init_set_str(ctx->state[3], "10325476", 16);
    mpz_init_set_str(ctx->state[4], "C3D2E1F0", 16);
    ctx->buffer_size = 0;
    mpz_init_set_ui(ctx->length, 0);
}

void ripemd160_update(RIPEMD160_CTX *ctx, const unsigned char *data, size_t len) {
    // Update the length
    mpz_t temp;
    mpz_init(temp);
    mpz_set_ui(temp, len * 8);
    mpz_add(ctx->length, ctx->length, temp);
    mpz_clear(temp);

    // Process full blocks
    while (len >= 64 - ctx->buffer_size) {
        memcpy(ctx->buffer + ctx->buffer_size, data, 64 - ctx->buffer_size);
        // TODO: Implement the compression function
        data += 64 - ctx->buffer_size;
        len -= 64 - ctx->buffer_size;
        ctx->buffer_size = 0;
    }

    // Copy remaining data to buffer
    if (len > 0) {
        memcpy(ctx->buffer + ctx->buffer_size, data, len);
        ctx->buffer_size += len;
    }
}

void ripemd160_final(RIPEMD160_CTX *ctx, unsigned char *digest) {
    // Pad the message
    size_t padding_size = (ctx->buffer_size < 56) ? (56 - ctx->buffer_size) : (120 - ctx->buffer_size);
    unsigned char padding[64] = {0x80};  // First byte is 0x80, rest are 0x00
    ripemd160_update(ctx, padding, padding_size);

    // Append the length
    unsigned char length_bytes[8];
    mpz_export(length_bytes, NULL, -1, 1, 0, 0, ctx->length);
    ripemd160_update(ctx, length_bytes, 8);

    // Copy the state to the digest
    for (int i = 0; i < 5; i++) {
        mpz_export(digest + i * 4, NULL, -1, 4, 0, 0, ctx->state[i]);
    }

    // Clear the context
    for (int i = 0; i < 5; i++) {
        mpz_clear(ctx->state[i]);
    }
    mpz_clear(ctx->length);
}

void ripemd160_hash(const unsigned char *data, size_t len, unsigned char *digest) {
    RIPEMD160_CTX ctx;
    ripemd160_init(&ctx);
    ripemd160_update(&ctx, data, len);
    ripemd160_final(&ctx, digest);
}

int main() {
    // const char *message = "Hello, world!";
    // 
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

    size_t message_len = strlen(sha256Hash);
    printf("Message length: %zu\n", message_len);

    unsigned char digest[RIPEMD160_DIGEST_SIZE];

    // Hash the message
    ripemd160_hash((const unsigned char *)sha256Hash, MY_SHA256_DIGEST_LENGTH, digest);

    // Print the digest
    printf("RIPEMD-160: ");
    for (int i = 0; i < RIPEMD160_DIGEST_SIZE; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    return 0;
}