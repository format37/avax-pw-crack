// ++ SHA ++
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define PBKDF2_SHA512_STATIC
#define PBKDF2_SHA512_IMPLEMENTATION
#include "pbkdf2_sha512.h"

#if defined(HAS_OSSL)
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#endif

void print_as_hex(const uint8_t *s,  const uint32_t slen)
{
	for (uint32_t i = 0; i < slen; i++)
	{
		printf("%02X%s", s[ i ], (i % 4 == 3) && (i != slen - 1) ? "-" : "");
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
		print_as_hex(ossl_one, len);
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
    print_as_hex(md, sizeof md);
	
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
	print_as_hex(md, sizeof md);
	
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
	print_as_hex(dk, dklen);
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

typedef struct {
    unsigned char chain_code[32];
    // Add other relevant fields like depth, index, etc.
} Bip32KeyData;

typedef struct {
    int some_field; // Placeholder
} Bip32KeyNetVersions;

typedef struct {
    unsigned char private_key[32];
    Bip32KeyData *key_data;
    Bip32KeyNetVersions *key_net_ver;
} Bip32Base;

void generate_master_key_and_chain_code(const unsigned char* seed, size_t seed_len,
                                        unsigned char* master_key, unsigned char* chain_code) {
    // Implement this function
}

Bip32Base* Bip32Base_FromSeed(
	const unsigned char *seed_bytes, 
	size_t seed_len, 
	Bip32KeyNetVersions *key_net_ver
	) {
    // Step 1: Input validation
    if (seed_len < 16) { // Minimum seed length requirement
        // Handle error
        return NULL;
    }

    // Step 2: Cryptographic operations
    unsigned char master_key[32];  // 256 bits
    unsigned char chain_code[32];  // 256 bits
	// TODO: Use HMAC-SHA512 to generate master_key and chain_code from seed_bytes
    generate_master_key_and_chain_code(seed_bytes, seed_len, master_key, chain_code);

    // Step 3: Data structures
    Bip32Base *bip32_obj = (Bip32Base*)malloc(sizeof(Bip32Base));
    //bip32_obj->private_key = (unsigned char*)malloc(32);
    memcpy(bip32_obj->private_key, master_key, 32);

    // Initialize key_data and key_net_ver (not shown here)

    // Step 4: Error handling is integrated within the steps

    return bip32_obj;
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

	/*printf("SHA512 of argv[1]:\n");
	compute_sha((uint8_t *) argv[1], strlen(argv[1]));
	printf("\n");
	
	printf("HMAC-SHA512 of argv[2] with key arg[1]:\n");
	compute_hmac((uint8_t *) argv[1], strlen(argv[1]), (uint8_t *) argv[2], strlen(argv[2]));
	printf("\n");*/
	
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
	print_as_hex(derived_key, sizeof derived_key);
	printf("\n");
	// Bip32Base_FromSeed
	Bip32Base *bip32_obj = Bip32Base_FromSeed(derived_key, sizeof derived_key, NULL);
	// print private key
	printf("Private key: ");
	print_as_hex(bip32_obj->private_key, sizeof bip32_obj->private_key);
	printf("\n");
	
	return 0;
}