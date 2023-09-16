// ++ SHA ++
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define PBKDF2_SHA512_STATIC
#define PBKDF2_SHA512_IMPLEMENTATION
#include "pbkdf2_sha512.h"

//#if defined(HAS_OSSL)
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
//#endif

void print_as_hex_hyphen(const uint8_t *s,  const uint32_t slen)
{
	for (uint32_t i = 0; i < slen; i++)
	{
		printf("%02X%s", s[ i ], (i % 4 == 3) && (i != slen - 1) ? "-" : "");
	}
	printf("\n");
}

void print_as_hex_uint(const uint8_t *data,  const uint32_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void print_as_hex_char(unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void check_with_ossl(const uint8_t *this_one, const uint8_t *ossl_one, uint32_t len,
    const char *what)
{
	if (memcmp(this_one, ossl_one, len) == 0)
	{
		printf(" *ossl %s matches.\n", what);
	}
	else
	{
		printf(" *ossl %s does not match. It was:\n", what);
		print_as_hex_uint(ossl_one, len);
	}
}

void compute_sha(const uint8_t *msg, uint32_t mlen)
{
	uint8_t md[SHA512_DIGESTLEN] = {0};  // Initialize to zero
    SHA512_CTX sha;
    sha512_init(&sha);

    sha512_update(&sha, msg, mlen);

    sha512_final(&sha, md);

    printf("Computed SHA-512: ");
    print_as_hex_uint(md, sizeof md);
	
#if defined(HAS_OSSL)
	uint8_t md_ossl[SHA512_DIGESTLEN];
	EVP_MD_CTX *sha_ossl = EVP_MD_CTX_new();
	EVP_DigestInit_ex(sha_ossl, EVP_sha512(), 0);
	EVP_DigestUpdate(sha_ossl, msg, mlen);
	EVP_DigestFinal_ex(sha_ossl, md_ossl, 0);
	
	EVP_MD_CTX_free(sha_ossl);
	
	check_with_ossl(md, md_ossl, sizeof md, "sha512");
#endif
}

void compute_hmac(const uint8_t *key, uint32_t klen, const uint8_t *msg, uint32_t mlen)
{
	uint8_t md[SHA512_DIGESTLEN];
	HMAC_SHA512_CTX hmac;
	hmac_sha512_init(&hmac, key, klen);
	hmac_sha512_update(&hmac, msg, mlen);
	hmac_sha512_final(&hmac, md);
	printf("Computed HMAC-SHA-512: ");
	print_as_hex_uint(md, sizeof md);
	
#if defined(HAS_OSSL)
	uint8_t md_ossl[SHA512_DIGESTLEN];
	HMAC_CTX *hmac_ossl = HMAC_CTX_new();
	HMAC_Init_ex(hmac_ossl, key, (int) klen, EVP_sha512(), 0);
	HMAC_Update(hmac_ossl, msg, mlen);
	HMAC_Final(hmac_ossl, md_ossl, 0);
	
	HMAC_CTX_free(hmac_ossl);
	
	check_with_ossl(md, md_ossl, sizeof md, "hmac-sha512");
	
#endif
}

void compute_pbkdf2(
	const uint8_t *key, 
	uint32_t klen, 
	const uint8_t *salt, 
	uint32_t slen,
    uint32_t rounds, 
	uint32_t dklen,
	unsigned char *derived_key
	)
{
	uint8_t *dk = malloc(dklen);
	HMAC_SHA512_CTX pbkdf_hmac;
	pbkdf2_sha512(&pbkdf_hmac, key, klen, salt, slen, rounds, dk, dklen);
	printf("Computed PBKDF2-SHA-512: ");
	print_as_hex_uint(dk, dklen);
	my_cuda_memcpy_unsigned_char(derived_key, dk, dklen);
	
	#if defined(HAS_OSSL)
		uint8_t *dk_ossl = malloc(dklen);
		// print that we are using openssl
		printf("Using OpenSSL\n");
		PKCS5_PBKDF2_HMAC((const char *) key, (int) klen, salt, (int) slen, (int) rounds,
						EVP_sha512(), (int) dklen, dk_ossl);
		
		check_with_ossl(dk, dk_ossl, dklen, "pbkdf2-sha512");
		free(dk_ossl);
	#endif
	free(dk);
}

#define DKLEN 64
#define ROUNDS 2048

// -- SHA --

// ++ bip32 From seed ++

void bip32_from_seed(const uint8_t *seed, uint32_t seed_len)
{
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
    print_as_hex_char(master_private_key, 32);
    printf("Chain Code: ");
    print_as_hex_char(chain_code, 32);
}

// -- bip32 From seed --

int main(int argc, char **argv)
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
	printf("Derived key: ");
	print_as_hex_uint(derived_key, sizeof derived_key);
	printf("\n");

	// master key
	bip32_from_seed(derived_key, sizeof derived_key);

    return 0;
}