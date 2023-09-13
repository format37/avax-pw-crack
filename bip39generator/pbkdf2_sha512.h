// The rotate operation for 64bits
#define ROR64(x,n) ((x >> n) | (x << (64 - n)))
#define CH(x,y,z)  (z ^ (x & (y ^ z)))
#define MAJ(x,y,z) ((x & y) | (z & (x | y)))
#define S0_64(x)   (ROR64((x), 28) ^ ROR64((x),  34) ^ ROR64((x), 39)) 
#define S1_64(x)   (ROR64((x), 14) ^ ROR64((x),  18) ^ ROR64((x), 41)) 
#define R0_64(x)   (ROR64((x), 1)  ^ ROR64((x),  8)  ^ ((x) >> 7)) 
#define R1_64(x)   (ROR64((x), 19) ^ ROR64((x), 61) ^ ((x) >> 6))

#ifndef PBKDF2_SHA512_INCLUDE
#define PBKDF2_SHA512_INCLUDE

#define SHA512_BLOCKLEN  128ul
#define SHA512_DIGESTLEN 64ul
#define SHA512_DIGESTINT 8ul

#ifndef PBKDF2_SHA512_STATIC
#define PBKDF2_SHA512_DEF extern
#else
#define PBKDF2_SHA512_DEF static
#endif

#include <stdint.h>
#include <string.h>

typedef struct sha512_ctx_t
{
    uint64_t len;  // Make sure this is uint64_t
    uint64_t h[SHA512_DIGESTINT];
    uint8_t buf[SHA512_BLOCKLEN];
} SHA512_CTX;

__device__ void sha512_init(SHA512_CTX *ctx);
__device__ void sha512_update(SHA512_CTX *ctx, const uint8_t *m, uint32_t mlen);
__device__ void sha512_final(SHA512_CTX *ctx, uint8_t *md);

typedef struct hmac_sha512_ctx_t
{
	uint8_t buf[SHA512_BLOCKLEN]; // key block buffer, not needed after init
	uint64_t h_inner[SHA512_DIGESTINT];
	uint64_t h_outer[SHA512_DIGESTINT];
	SHA512_CTX sha;
} HMAC_SHA512_CTX;

PBKDF2_SHA512_DEF __device__ void hmac_sha512_init(HMAC_SHA512_CTX *hmac, const uint8_t *key, uint32_t keylen);
PBKDF2_SHA512_DEF __device__ void hmac_sha512_update(HMAC_SHA512_CTX *hmac, const uint8_t *m, uint32_t mlen);
// resets state to hmac_sha512_init
PBKDF2_SHA512_DEF __device__ void hmac_sha512_final(HMAC_SHA512_CTX *hmac, uint8_t *md);

PBKDF2_SHA512_DEF void pbkdf2_sha512(HMAC_SHA512_CTX *ctx,
    const uint8_t *key, uint32_t keylen, const uint8_t *salt, uint32_t saltlen, uint32_t rounds,
    uint8_t *dk, uint32_t dklen);

#endif // PBKDF2_SHA512_INCLUDE

//------------------------------------------------------------------------------

#ifdef PBKDF2_SHA512_IMPLEMENTATION

#include <string.h>

static uint32_t ror(uint32_t n, uint32_t k)
{
	return (n >> k) | (n << (32 - k));
}

#define ROR(n,k) ror(n,k)

#define CH(x,y,z)  (z ^ (x & (y ^ z)))
#define MAJ(x,y,z) ((x & y) | (z & (x | y)))
#define S0(x)      (ROR(x, 2) ^ ROR(x,13) ^ ROR(x,22))
#define S1(x)      (ROR(x, 6) ^ ROR(x,11) ^ ROR(x,25))
#define R0(x)      (ROR(x, 7) ^ ROR(x,18) ^ (x>>3))
#define R1(x)      (ROR(x,17) ^ ROR(x,19) ^ (x>>10))

#define INNER_PAD '\x36'
#define OUTER_PAD '\x5c'

PBKDF2_SHA512_DEF __device__ void hmac_sha512_init(HMAC_SHA512_CTX *hmac, const uint8_t *key, uint32_t keylen)
{
	SHA512_CTX *sha = &hmac->sha;
	
	if (keylen <= SHA512_BLOCKLEN)
	{
		for (int i = 0; i < keylen; ++i) {hmac->buf[i] = key[i];}
		memset(hmac->buf + keylen, '\0', SHA512_BLOCKLEN - keylen);
	}
	else
	{
		sha512_init(sha);
		sha512_update(sha, key, keylen);
		sha512_final(sha, hmac->buf);
		memset(hmac->buf + SHA512_DIGESTLEN, '\0', SHA512_BLOCKLEN - SHA512_DIGESTLEN);
	}
	
	uint32_t i;
	for (i = 0; i < SHA512_BLOCKLEN; i++)
	{
		hmac->buf[ i ] = hmac->buf[ i ] ^ OUTER_PAD;
	}
	
	sha512_init(sha);
	sha512_update(sha, hmac->buf, SHA512_BLOCKLEN);
	// copy outer state
	for (int i = 0; i < SHA512_DIGESTLEN; ++i) {hmac->h_outer[i] = sha->h[i];}
	
	for (i = 0; i < SHA512_BLOCKLEN; i++)
	{
		hmac->buf[ i ] = (hmac->buf[ i ] ^ OUTER_PAD) ^ INNER_PAD;
	}
	
	sha512_init(sha);
	sha512_update(sha, hmac->buf, SHA512_BLOCKLEN);
	// copy inner state
	for (int i = 0; i < SHA512_DIGESTLEN; ++i) {hmac->h_inner[i] = sha->h[i];}
}

PBKDF2_SHA512_DEF __device__ void hmac_sha512_update(HMAC_SHA512_CTX *hmac, const uint8_t *m, uint32_t mlen)
{
	sha512_update(&hmac->sha, m, mlen);
}

PBKDF2_SHA512_DEF __device__ void hmac_sha512_final(HMAC_SHA512_CTX *hmac, uint8_t *md)
{
	SHA512_CTX *sha = &hmac->sha;
	sha512_final(sha, md);
	
	// reset sha to outer state
	for (int i = 0; i < SHA512_DIGESTLEN; ++i) {sha->h[i] = hmac->h_outer[i];}
	sha->len = SHA512_BLOCKLEN;
	
	sha512_update(sha, md, SHA512_DIGESTLEN);
	sha512_final(sha, md); // md = D(outer || D(inner || msg))
	
	// reset sha to inner state -> reset hmac
	for (int i = 0; i < SHA512_DIGESTLEN; ++i) {sha->h[i] = hmac->h_inner[i];}
	sha->len = SHA512_BLOCKLEN;
}

PBKDF2_SHA512_DEF void pbkdf2_sha512(HMAC_SHA512_CTX *hmac,
    const uint8_t *key, uint32_t keylen, const uint8_t *salt, uint32_t saltlen, uint32_t rounds,
    uint8_t *dk, uint32_t dklen)
{
	uint32_t hlen = SHA512_DIGESTLEN;
	uint32_t l = dklen / hlen + ((dklen % hlen) ? 1 : 0);
	uint32_t r = dklen - (l - 1) * hlen;
	
	hmac_sha512_init(hmac, key, keylen);
	
	uint8_t *U = hmac->buf;
	uint8_t *T = dk;
	uint8_t count[4];
	
	uint32_t i, j, k;
	uint32_t len = hlen;
	for (i = 1; i <= l; i++)
	{
		if (i == l) { len = r; }
		count[0] = (i >> 24) & 0xFF;
		count[1] = (i >> 16) & 0xFF;
		count[2] = (i >>  8) & 0xFF;
		count[3] = (i) & 0xFF;
		hmac_sha512_update(hmac, salt, saltlen);
		hmac_sha512_update(hmac, count, 4);
		hmac_sha512_final(hmac, U);
		for (int i = 0; i < len; ++i) {T[i] = U[i];}
		for (j = 1; j < rounds; j++)
		{
			hmac_sha512_update(hmac, U, hlen);
			hmac_sha512_final(hmac, U);
			for (k = 0; k < len; k++)
			{
				T[k] ^= U[k];
			}
		}
		T += len;
	}
	
}

#endif // PBKDF2_SHA512_IMPLEMENTATION

/*
------------------------------------------------------------------------------
This software is available under 2 licenses -- choose whichever you prefer.
------------------------------------------------------------------------------
ALTERNATIVE A - Public Domain (www.unlicense.org)
This is free and unencumbered software released into the public domain.
Anyone is free to copy, modify, publish, use, compile, sell, or distribute this
software, either in source code form or as a compiled binary, for any purpose,
commercial or non-commercial, and by any means.
In jurisdictions that recognize copyright laws, the author or authors of this
software dedicate any and all copyright interest in the software to the public
domain. We make this dedication for the benefit of the public at large and to
the detriment of our heirs and successors. We intend this dedication to be an
overt act of relinquishment in perpetuity of all present and future rights to
this software under copyright law.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
------------------------------------------------------------------------------
ALTERNATIVE B - MIT License
Copyright (c) 2019 monolifed
Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
------------------------------------------------------------------------------
*/
