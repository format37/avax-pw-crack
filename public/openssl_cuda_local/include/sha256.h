// #include <cuda_runtime.h>
#include <cstdint>

// #define CH(x,y,z)  ((z) ^ ((x) & ((y) ^ (z)))) // SHA256 version
// #define MAJ(x,y,z) (((x) & (y)) | ((z) & ((x) | (y)))) // SHA256 version

// o1 suggestion:
// #define CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
// #define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define CH(x,y,z)  (z ^ (x & (y ^ z))) // pbkdf2 version
#define MAJ(x,y,z) ((x & y) | (z & (x | y))) // pbkdf2 version

#define ROTR(x,n)  (((x) >> (n)) | ((x) << (32 - (n))))
#define S0(x)      (ROTR(x, 2) ^ ROTR(x,13) ^ ROTR(x,22))
#define S1(x)      (ROTR(x, 6) ^ ROTR(x,11) ^ ROTR(x,25))
#define s0(x)      (ROTR(x, 7) ^ ROTR(x,18) ^ ((x) >> 3))
#define s1(x)      (ROTR(x,17) ^ ROTR(x,19) ^ ((x) >> 10))

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

__device__ __constant__ uint32_t d_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

struct SHA256_CTX_CUDA {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[SHA256_BLOCK_SIZE];
};

__device__ __constant__ SHA256_CTX_CUDA global_ctx = {
    {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19},
    0,
    {0}
};

__device__ void sha256_transform(SHA256_CTX_CUDA *ctx, const uint8_t *data) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    for (; i < 64; ++i)
        m[i] = s1(m[i - 2]) + m[i - 7] + s0(m[i - 15]) + m[i - 16];

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + S1(e) + CH(e, f, g) + d_K[i] + m[i];
        t2 = S0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

__device__ void sha256_update(SHA256_CTX_CUDA *ctx, const uint8_t *data, size_t len) {
    size_t i;

    for (i = 0; i < len; ++i) {
        ctx->buffer[ctx->count % 64] = data[i];
        ctx->count++;
        if ((ctx->count % 64) == 0) {
            sha256_transform(ctx, ctx->buffer);
        }
    }
}

__device__ void sha256_final(SHA256_CTX_CUDA *ctx, uint8_t *hash) {
    uint32_t i;
    uint64_t bits_count = ctx->count * 8;

    // Pad the message
    ctx->buffer[ctx->count % 64] = 0x80;
    ctx->count++;

    // If we don't have room for the length (8 bytes), transform this block and pad the next one
    if ((ctx->count % 64) > 56) {
        while ((ctx->count % 64) != 0) {
            ctx->buffer[ctx->count % 64] = 0;
            ctx->count++;
        }
        sha256_transform(ctx, ctx->buffer);
    }

    // Pad up to 56 bytes (leaving 8 for the length)
    while ((ctx->count % 64) < 56) {
        ctx->buffer[ctx->count % 64] = 0;
        ctx->count++;
    }

    // Append the length in big-endian format
    for (i = 0; i < 8; i++) {
        ctx->buffer[56 + i] = (bits_count >> ((7 - i) * 8)) & 0xFF;
    }

    sha256_transform(ctx, ctx->buffer);

    // Output the hash
    for (i = 0; i < 8; i++) {
        hash[i * 4] = (ctx->state[i] >> 24) & 0xFF;
        hash[i * 4 + 1] = (ctx->state[i] >> 16) & 0xFF;
        hash[i * 4 + 2] = (ctx->state[i] >> 8) & 0xFF;
        hash[i * 4 + 3] = ctx->state[i] & 0xFF;
    }
}

__device__ void compute_sha256(const uint8_t *msg, uint32_t mlen, uint8_t *outputHash) {
    SHA256_CTX_CUDA ctx = global_ctx;
    sha256_update(&ctx, msg, mlen);
    sha256_final(&ctx, outputHash);
}