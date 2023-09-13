#include <cstdint>
#include "pbkdf2_sha512.h"

__device__ static const uint64_t K[80] = {
    UINT64_C(0x428a2f98d728ae22), UINT64_C(0x7137449123ef65cd),
    UINT64_C(0xb5c0fbcfec4d3b2f), UINT64_C(0xe9b5dba58189dbbc),
    UINT64_C(0x3956c25bf348b538), UINT64_C(0x59f111f1b605d019),
    UINT64_C(0x923f82a4af194f9b), UINT64_C(0xab1c5ed5da6d8118),
    UINT64_C(0xd807aa98a3030242), UINT64_C(0x12835b0145706fbe),
    UINT64_C(0x243185be4ee4b28c), UINT64_C(0x550c7dc3d5ffb4e2),
    UINT64_C(0x72be5d74f27b896f), UINT64_C(0x80deb1fe3b1696b1),
    UINT64_C(0x9bdc06a725c71235), UINT64_C(0xc19bf174cf692694),
    UINT64_C(0xe49b69c19ef14ad2), UINT64_C(0xefbe4786384f25e3),
    UINT64_C(0x0fc19dc68b8cd5b5), UINT64_C(0x240ca1cc77ac9c65),
    UINT64_C(0x2de92c6f592b0275), UINT64_C(0x4a7484aa6ea6e483),
    UINT64_C(0x5cb0a9dcbd41fbd4), UINT64_C(0x76f988da831153b5),
    UINT64_C(0x983e5152ee66dfab), UINT64_C(0xa831c66d2db43210),
    UINT64_C(0xb00327c898fb213f), UINT64_C(0xbf597fc7beef0ee4),
    UINT64_C(0xc6e00bf33da88fc2), UINT64_C(0xd5a79147930aa725),
    UINT64_C(0x06ca6351e003826f), UINT64_C(0x142929670a0e6e70),
    UINT64_C(0x27b70a8546d22ffc), UINT64_C(0x2e1b21385c26c926),
    UINT64_C(0x4d2c6dfc5ac42aed), UINT64_C(0x53380d139d95b3df),
    UINT64_C(0x650a73548baf63de), UINT64_C(0x766a0abb3c77b2a8),
    UINT64_C(0x81c2c92e47edaee6), UINT64_C(0x92722c851482353b),
    UINT64_C(0xa2bfe8a14cf10364), UINT64_C(0xa81a664bbc423001),
    UINT64_C(0xc24b8b70d0f89791), UINT64_C(0xc76c51a30654be30),
    UINT64_C(0xd192e819d6ef5218), UINT64_C(0xd69906245565a910),
    UINT64_C(0xf40e35855771202a), UINT64_C(0x106aa07032bbd1b8),
    UINT64_C(0x19a4c116b8d2d0c8), UINT64_C(0x1e376c085141ab53),
    UINT64_C(0x2748774cdf8eeb99), UINT64_C(0x34b0bcb5e19b48a8),
    UINT64_C(0x391c0cb3c5c95a63), UINT64_C(0x4ed8aa4ae3418acb),
    UINT64_C(0x5b9cca4f7763e373), UINT64_C(0x682e6ff3d6b2b8a3),
    UINT64_C(0x748f82ee5defb2fc), UINT64_C(0x78a5636f43172f60),
    UINT64_C(0x84c87814a1f0ab72), UINT64_C(0x8cc702081a6439ec),
    UINT64_C(0x90befffa23631e28), UINT64_C(0xa4506cebde82bde9),
    UINT64_C(0xbef9a3f7b2c67915), UINT64_C(0xc67178f2e372532b),
    UINT64_C(0xca273eceea26619c), UINT64_C(0xd186b8c721c0c207),
    UINT64_C(0xeada7dd6cde0eb1e), UINT64_C(0xf57d4f7fee6ed178),
    UINT64_C(0x06f067aa72176fba), UINT64_C(0x0a637dc5a2c898a6),
    UINT64_C(0x113f9804bef90dae), UINT64_C(0x1b710b35131c471b),
    UINT64_C(0x28db77f523047d84), UINT64_C(0x32caab7b40c72493),
    UINT64_C(0x3c9ebe0a15c9bebc), UINT64_C(0x431d67c49c100d4c),
    UINT64_C(0x4cc5d4becb3e42b6), UINT64_C(0x597f299cfc657e2a),
    UINT64_C(0x5fcb6fab3ad6faec), UINT64_C(0x6c44198c4a475817),
};

__device__ size_t my_strlen(const char *str) {
    size_t len = 0;
    while (*str != '\0') {
        ++len;
        ++str;
    }
    return len;
}

__device__ void print_as_hex(const uint8_t *s,  const uint32_t slen)
{
	for (uint32_t i = 0; i < slen; i++)
	{
		printf("%02X%s", s[ i ], (i % 4 == 3) && (i != slen - 1) ? "-" : "");
	}
	printf("\n");
}

__device__ void sha512_init(SHA512_CTX *s)
{
	s->len = 0;
	s->h[0] = 0x6a09e667f3bcc908ULL;
	s->h[1] = 0xbb67ae8584caa73bULL;
	s->h[2] = 0x3c6ef372fe94f82bULL;
	s->h[3] = 0xa54ff53a5f1d36f1ULL;
	s->h[4] = 0x510e527fade682d1ULL;
	s->h[5] = 0x9b05688c2b3e6c1fULL;
	s->h[6] = 0x1f83d9abfb41bd6bULL;
	s->h[7] = 0x5be0cd19137e2179ULL;
}

__device__ static void sha512_transform(SHA512_CTX *s, const uint8_t *buf)
{
    uint64_t t1, t2, a, b, c, d, e, f, g, h, m[80]; // Change to uint64_t and m[80]
    uint32_t i, j;

    for (i = 0, j = 0; i < 16; i++, j += 8) // Modify loop to collect 8 bytes for each entry in m
    {
        m[i] = ((uint64_t)buf[j] << 56) | ((uint64_t)buf[j + 1] << 48) |
               ((uint64_t)buf[j + 2] << 40) | ((uint64_t)buf[j + 3] << 32) |
               ((uint64_t)buf[j + 4] << 24) | ((uint64_t)buf[j + 5] << 16) |
               ((uint64_t)buf[j + 6] << 8) | ((uint64_t)buf[j + 7]);
    }
    for (; i < 80; i++) // Increase loop limit to 80
    {
        m[i] = R1_64(m[i - 2]) + m[i - 7] + R0_64(m[i - 15]) + m[i - 16];
    }

    a = s->h[0];
    b = s->h[1];
    c = s->h[2];
    d = s->h[3];
    e = s->h[4];
    f = s->h[5];
    g = s->h[6];
    h = s->h[7];

    for (i = 0; i < 80; i++) // Increase loop limit to 80
    {
        t1 = h + S1_64(e) + CH(e, f, g) + K[i] + m[i];
        t2 = S0_64(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

	s->h[0] += a;
	s->h[1] += b;
	s->h[2] += c;
	s->h[3] += d;
	s->h[4] += e;
	s->h[5] += f;
	s->h[6] += g;
	s->h[7] += h;
}

__device__ void sha512_update(SHA512_CTX *s, const uint8_t *m, uint32_t len)
{
	const uint8_t *p = m;
	uint32_t r = s->len % SHA512_BLOCKLEN;
	
	s->len += len;
	if (r)
	{
		if (len + r < SHA512_BLOCKLEN)
		{
            for (int i = 0; i < len; ++i) {s->buf[r + i] = p[i];}
			return;
		}
        for (int i = 0; i < SHA512_BLOCKLEN - r; ++i) {s->buf[r + i] = p[i];}
		len -= SHA512_BLOCKLEN - r;
		p += SHA512_BLOCKLEN - r;
		sha512_transform(s, s->buf);
	}
	for (; len >= SHA512_BLOCKLEN; len -= SHA512_BLOCKLEN, p += SHA512_BLOCKLEN)
	{
		sha512_transform(s, p);
	}
	for (int i = 0; i < len; ++i) {s->buf[i] = p[i];}
	// Debug line to print the block being processed
    printf("Processing block: ");
    for (int i = 0; i < SHA512_BLOCKLEN && i < len; ++i) {
        printf("%02x ", m[i]);
    }
    printf("\n");
}

__device__ void sha512_final(SHA512_CTX *s, uint8_t *md)
{
	uint32_t r = s->len % SHA512_BLOCKLEN;
	uint64_t totalBits = s->len * 8;  // Total bits
	uint64_t len_lower = totalBits & 0xFFFFFFFFFFFFFFFFULL;  // Lower 64 bits
    uint64_t len_upper = totalBits >> 64;  // Upper 64 bits
	
    // Pad message
    s->buf[r++] = 0x80;
    while (r < 112)  // Padding until the total length is 112
    {
        s->buf[r++] = 0x00;
    }

    // Write 128 bit processed length in big-endian
    for (int i = 0; i < 8; ++i)
    {
		s->buf[r++] = (len_upper >> (8 * (7 - i))) & 0xFF;
	}

	for (int i = 0; i < 8; ++i)
    {
		s->buf[r++] = (len_lower >> (8 * (7 - i))) & 0xFF;
	}
	sha512_transform(s, s->buf);
	
	for (uint32_t i = 0; i < SHA512_DIGESTINT; i++)
	{
		md[8 * i    ] = s->h[i] >> 56;
		md[8 * i + 1] = s->h[i] >> 48;
		md[8 * i + 2] = s->h[i] >> 40;
		md[8 * i + 3] = s->h[i] >> 32;
		md[8 * i + 4] = s->h[i] >> 24;
		md[8 * i + 5] = s->h[i] >> 16;
		md[8 * i + 6] = s->h[i] >> 8;
		md[8 * i + 7] = s->h[i];
	}
	sha512_init(s);
}

__device__ void compute_sha(const uint8_t *msg, uint32_t mlen)
{
	uint8_t md[SHA512_DIGESTLEN] = {0};  // Initialize to zero
    SHA512_CTX sha;
    sha512_init(&sha);
    sha512_update(&sha, msg, mlen);
    sha512_final(&sha, md);
    print_as_hex(md, sizeof md);
}

__global__ void Bip39SeedGenerator() {
    // Convert the mnemonic and passphrase to byte arrays (or use them as-is if you can)
    uint8_t *m_mnemonic = (unsigned char *)"sell stereo useless course suffer tribe jazz monster fresh excess wire again father film sudden pelican always room attack rubber pelican trash alone cancel";
    /*unsigned char derived_key[64];  // This will hold the generated seed

    // Initialize derived_key to zeros
    for (int i = 0; i < 64; ++i) {
        derived_key[i] = 0;
    }*/

    // Preparing salt = "mnemonicTESTPHRASG"
    //const unsigned char *salt = (unsigned char *)"mnemonicTESTPHRASG";

    //  print my_strlen((const char*) m_mnemonic)
    printf("Mnemonic length: %d\n", my_strlen((const char*) m_mnemonic));

    //compute_sha((uint8_t *) m_mnemonic, strlen(m_mnemonic));
    compute_sha((uint8_t *) m_mnemonic, my_strlen((const char*) m_mnemonic));

    // Call pbkdf2_hmac to perform the key derivation
    //pbkdf2_hmac(m_mnemonic, salt, derived_key);
}
