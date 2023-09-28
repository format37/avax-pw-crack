// ++ pbdkf2 ++
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define PBKDF2_SHA512_STATIC
#define PBKDF2_SHA512_IMPLEMENTATION
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
//#include <openssl/sha.h>
#include "pbkdf2_sha256.h"
#include "pbkdf2_sha512.h"

#include <openssl/ripemd.h>
#include <stdint.h>
#define MY_SHA256_DIGEST_LENGTH 32
#define CHARSET "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
#define CHECKSUM_LENGTH 6

// ++ Declarations ++
__device__ void print_as_hex_char(unsigned char *data, int len);
//void my_cuda_memcpy_unsigned_char(unsigned char *dest, const unsigned char *src, size_t len);  // Assuming this function is defined elsewhere
// -- Declarations --

__device__ void my_cuda_memcpy_unsigned_char(uint8_t *dst, const uint8_t *src, unsigned int n) {
    for (unsigned int i = 0; i < n; ++i) {
        dst[i] = src[i];
    }
}

__device__ void print_as_hex_hyphen(const uint8_t *s,  const uint32_t slen)
{
	for (uint32_t i = 0; i < slen; i++)
	{
		printf("%02X%s", s[ i ], (i % 4 == 3) && (i != slen - 1) ? "-" : "");
	}
	printf("\n");
}

__device__ void print_as_hex_uint(const uint8_t *data,  const uint32_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}
/*
void print_as_hex_char(unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}*/

__device__ int device_memcmp(const uint8_t *ptr1, const uint8_t *ptr2, uint32_t len)
{
    for (uint32_t i = 0; i < len; ++i)
    {
        if (ptr1[i] < ptr2[i])
            return -1;
        if (ptr1[i] > ptr2[i])
            return 1;
    }
    return 0;
}

__device__ void check_with_ossl(const uint8_t *this_one, const uint8_t *ossl_one, uint32_t len,
    const char *what)
{
	//if (memcmp(this_one, ossl_one, len) == 0)
    if (device_memcmp(this_one, ossl_one, len) == 0)
	{
		printf(" *ossl %s matches.\n", what);
	}
	else
	{
		printf(" *ossl %s does not match. It was:\n", what);
		print_as_hex_uint(ossl_one, len);
	}
}

__device__ void compute_sha(const uint8_t *msg, size_t mlen)
{
	/*uint8_t md[SHA512_DIGESTLEN] = {0};  // Initialize to zero
    SHA512_CTX sha;
    sha512_init(&sha);

    sha512_update(&sha, msg, mlen);

    sha512_final(&sha, md);*/
    // SHA512_DIGESTLEN 64ul
    uint8_t md[64ul] = {0};  // Initialize to zero
    SHA512_CTX sha512;
    SHA512_Init(&sha512);
    SHA512_Update(&sha512, msg, mlen);
    SHA512_Final(md, &sha512);

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

__device__ void compute_hmac(const uint8_t *key, uint32_t klen, const uint8_t *msg, size_t mlen)
{
	//uint8_t md[64ul];
	/*HMAC_SHA512_CTX hmac;
	hmac_sha512_init(&hmac, key, klen);
	hmac_sha512_update(&hmac, msg, mlen);
	hmac_sha512_final(&hmac, md);*/
    unsigned char md[64ul]; // Use OpenSSL's SHA512_DIGEST_LENGTH instead of hardcoding
    unsigned int md_len;  // Length of the output hash
    if (klen > INT_MAX || mlen > INT_MAX) {
        // Handle error, perhaps return a specific error code or print an error message.
        printf("Error: klen or mlen is too large\n");
        return;
    }

    // Using OpenSSL's HMAC function
    //HMAC(EVP_sha512(), key, klen, msg, mlen, md, &md_len);
    HMAC(EVP_sha512(), key, (int)klen, msg, (size_t)mlen, md, &md_len);

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

__device__ void compute_pbkdf2(
	const uint8_t *key, 
	uint32_t klen, 
	const uint8_t *salt, 
	uint32_t slen,
    uint32_t rounds, 
	uint32_t dklen,
	unsigned char *derived_key
	)
{
    if (klen > INT_MAX || slen > INT_MAX || rounds > INT_MAX || dklen > INT_MAX) {
        // Handle error, perhaps return a specific error code or print an error message.
        printf("Error: klen, slen, rounds, or dklen is too large\n");
        return;
    }
	//uint8_t *dk = malloc(dklen);
    uint8_t *dk = (uint8_t *) malloc(dklen);
	//HMAC_SHA512_CTX pbkdf_hmac;
	//pbkdf2_sha512(&pbkdf_hmac, key, klen, salt, slen, rounds, dk, dklen);
    if (dk == NULL) {
        // Handle memory allocation failure
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    // Check if uint32_t values can fit into int
    if (klen > INT_MAX || slen > INT_MAX || rounds > INT_MAX || dklen > INT_MAX) {
        // Handle error: these values are too large to be safely cast to int
        fprintf(stderr, "One of the uint32_t values is too large to fit into an int.\n");
        exit(1);  // Or other error handling
    }
    // Using OpenSSL's PBKDF2 function
    if (PKCS5_PBKDF2_HMAC(
        (const char *)key,
        klen,
        salt,
        slen,
        rounds,
        EVP_sha512(),
        dklen,
        dk
    ) == 0)
    {
        // Handle error
        fprintf(stderr, "Error in PBKDF2\n");
        free(dk);
        exit(1);
    }
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
__device__ typedef struct {
    unsigned char master_private_key[32];
    unsigned char chain_code[32];
} BIP32Info;

__device__ BIP32Info bip32_from_seed(const uint8_t *seed, uint32_t seed_len)
{
	BIP32Info info;
	// HMAC-SHA512
    unsigned char hash[64];
    unsigned int len = 64;
    HMAC(EVP_sha512(), "Bitcoin seed", 12, seed, seed_len, hash, &len);
    // Split the hash into the master private key and chain code
    memcpy(info.master_private_key, hash, 32);
    memcpy(info.chain_code, hash + 32, 32);
    return info;
}
// -- bip32 From seed --

// ++ Child key derivation ++
__device__ void reverse_byte_array(uint8_t *arr, size_t len) {
    for(size_t i = 0; i < len / 2; i++) {
        uint8_t tmp = arr[i];
        arr[i] = arr[len - i - 1];
        arr[len - i - 1] = tmp;
    }
}

// Debug print for OpenSSL BIGNUM
__device__ void print_bn(const char* label, const BIGNUM* bn) {
	char* bn_str = BN_bn2dec(bn);
	printf("%s: %s\n", label, bn_str);
	OPENSSL_free(bn_str);
}

__device__ void test_reverse_byte_array() {
    uint8_t arr[4] = {0x01, 0x02, 0x03, 0x04};
    reverse_byte_array(arr, 4);
    for (int i = 0; i < 4; i++) {
        printf("%02x ", arr[i]);
    }
    printf("\n");
}

__device__ unsigned char *GetPublicKey(unsigned char *privateKeyBytes, size_t privateKeyLen, size_t *publicKeyLen) {
    EC_GROUP *curve = NULL;
    EC_KEY *eckey = NULL;
    BIGNUM *privateKey = NULL;
    EC_POINT *pub_key = NULL;
    unsigned char *publicKeyBytes = NULL;
    
    curve = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (curve == NULL) {
        return NULL;
    }

    eckey = EC_KEY_new();
    if (eckey == NULL) {
        return NULL;
    }
    
    if (!EC_KEY_set_group(eckey, curve)) {
        return NULL;
    }

    privateKey = BN_bin2bn(privateKeyBytes, privateKeyLen, NULL);
    if (privateKey == NULL) {
        return NULL;
    }
    
    if (!EC_KEY_set_private_key(eckey, privateKey)) {
        return NULL;
    }
    
    pub_key = EC_POINT_new(curve);
    if (pub_key == NULL) {
        return NULL;
    }

    if (!EC_POINT_mul(curve, pub_key, privateKey, NULL, NULL, NULL)) {
        return NULL;
    }

    EC_KEY_set_public_key(eckey, pub_key);

    *publicKeyLen = EC_POINT_point2oct(EC_KEY_get0_group(eckey), EC_KEY_get0_public_key(eckey), POINT_CONVERSION_COMPRESSED, NULL, 0, NULL);
    //publicKeyBytes = (unsigned char *) malloc(*publicKeyLen);
    publicKeyBytes = (unsigned char *) malloc((size_t) *publicKeyLen);

    if (publicKeyBytes == NULL) {
        return NULL;
    }

    //EC_POINT_point2oct(EC_KEY_get0_group(eckey), EC_KEY_get0_public_key(eckey), POINT_CONVERSION_COMPRESSED, publicKeyBytes, *publicKeyLen, NULL);
    EC_POINT_point2oct(EC_KEY_get0_group(eckey), EC_KEY_get0_public_key(eckey), POINT_CONVERSION_COMPRESSED, publicKeyBytes, (size_t) *publicKeyLen, NULL);
    
    EC_GROUP_free(curve);
    EC_KEY_free(eckey);
    EC_POINT_free(pub_key);
    BN_free(privateKey);

    return publicKeyBytes;
}


__device__ BIP32Info GetChildKeyDerivation(uint8_t* key, uint8_t* chainCode, uint32_t index) {
    test_reverse_byte_array();
	static int chain_counter = 0;
    static char path[100] = ""; // Assuming path length won't exceed 100
    printf("\n* step %d index: %u\n", chain_counter, index);
    chain_counter++; // Increment the counter for the next step
	
    // Update the path variable
    /*if ((index & 0x80000000) != 0) {
        snprintf(path, sizeof(path), "%s/%uH", path, index);
    } else {
        snprintf(path, sizeof(path), "%s/%u", path, index);
    }*/

    // Print the full derivation path
    printf("  * chain path: %s\n", path);

    // BigEndianBuffer equivalent
    uint8_t buffer[100]; // Assuming buffer length won't exceed 100
    size_t buffer_len = 0;

    if (index == 0) {
		printf("    * INDEX is 0\n");
		size_t publicKeyLen = 0;
		unsigned char *publicKeyBytes = GetPublicKey(key, 32, &publicKeyLen);
		print_as_hex_char(publicKeyBytes, publicKeyLen);
		//buffer[0] = 0x02;
		//memcpy(buffer + 1, publicKeyBytes + 1, 32);
		memcpy(buffer, publicKeyBytes, 33);  // Copies the entire 33-byte compressed public key including the first byte
		buffer_len += 33;		
    } else {
        buffer[0] = 0;
        memcpy(buffer + 1, key, 32);
        buffer_len += 33;
    }

    // Write index in big-endian format
    buffer[buffer_len++] = (index >> 24) & 0xFF;
    buffer[buffer_len++] = (index >> 16) & 0xFF;
    buffer[buffer_len++] = (index >> 8) & 0xFF;
    buffer[buffer_len++] = index & 0xFF;

    // HMAC-SHA512
    unsigned int len = 64;
    uint8_t hash[64];
    HMAC(EVP_sha512(), chainCode, 32, buffer, buffer_len, hash, &len);

    // Display debug information
	printf("      * C Pre-HMAC variable key:");
	print_as_hex_char(key, 32);
	printf("      * C Pre-HMAC Buffer:");
	print_as_hex_char(buffer, buffer_len);
	printf("      * C Pre-HMAC Key:");
	print_as_hex_char(chainCode, 32);

	// Slice the hash into 'il' and 'ir'
    uint8_t il[32], ir[32];
    memcpy(il, hash, 32);
    memcpy(ir, hash + 32, 32);

    // Print 'il' and 'ir'
    printf("    * il: ");
    print_as_hex_char(il, 32);
    printf("    * ir: ");
    print_as_hex_char(ir, 32);

	// Initialize OpenSSL big numbers
    BIGNUM *a = BN_new();
    BIGNUM *parentKeyInt = BN_new();
    BIGNUM *curveOrder = BN_new();
    BIGNUM *newKey = BN_new();
    BN_CTX *ctx = BN_CTX_new();

	// Set curve order for secp256k1
	BN_dec2bn(&curveOrder, "115792089237316195423570985008687907852837564279074904382605163141518161494337");

	// Print curve order for verification
	print_bn("Curve Order", curveOrder);

	// Convert byte arrays to big numbers
	BN_bin2bn(il, 32, a);
	BN_bin2bn(key, 32, parentKeyInt);

	// Debug prints before BN_mod_add
	print_bn("Debug C a (Before mod_add)", a);
	print_bn("Debug C parentKeyInt (Before mod_add)", parentKeyInt);
	print_bn("Debug C curveOrder (Before mod_add)", curveOrder);

	// Intermediate manual addition
	BIGNUM *tempSum = BN_new();
	BN_add(tempSum, a, parentKeyInt);
	print_bn("Debug C Temp Sum (a + parentKeyInt)", tempSum);
	BN_free(tempSum);

	// Perform BN_mod_add
	if (BN_mod_add(newKey, a, parentKeyInt, curveOrder, ctx) != 1) {
		printf("Error in BN_mod_add\n");
	}

	// Debug print after BN_mod_add
	print_bn("Debug C newKey (After mod_add)", newKey);

	BIP32Info info;
	int cmpResult = BN_cmp(a, curveOrder);
	if (cmpResult < 0 && !BN_is_zero(newKey)) {
		uint8_t newKeyBytes[32] = {0};  // Initialize to zero

		// Debugging: Print length before conversion
		int newKeyLen = 0;
		printf("newKeyLen before BN_bn2bin: %d\n", newKeyLen);

		// Convert newKey to byte array
		print_bn("Debug C newKey (Before BN_bn2bin)", newKey);
		newKeyLen = BN_bn2bin(newKey, newKeyBytes);
		print_bn("Debug C newKey (After BN_bn2bin)", newKey);

		// Debugging: Print length and hex dump after conversion
		printf("newKeyLen after BN_bn2bin: %d\n", newKeyLen);
		printf("newKeyBytes before reverse: ");
		print_as_hex_char(newKeyBytes, newKeyLen);

		// Reverse byte array for big-endian
		//reverse_byte_array(newKeyBytes, newKeyLen);

		// Debugging: Print hex dump after reverse
		printf("newKeyBytes after reverse: ");
		print_as_hex_char(newKeyBytes, newKeyLen);

        
        // Output newKeyBytes and ir (ChainCode)
        printf("  * chain code:");
		print_as_hex_char(ir, 32);
		printf("  * private:");
		print_as_hex_char(newKeyBytes, 32);
		printf("  * public:");
		size_t publicKeyLen = 0;
		unsigned char *publicKeyBytes = GetPublicKey(newKeyBytes, 32, &publicKeyLen);
		print_as_hex_char(publicKeyBytes, publicKeyLen);


		
		memcpy(info.master_private_key, newKeyBytes, 32);
		memcpy(info.chain_code, ir, 32);		

        // If newKeyBytes is less than 32 bytes, you'll need to pad with zeros at the beginning.
        // If it's more than 32 bytes, you'll need to truncate. This can be done here.
    } else {
        printf("C GetChildKeyDerivation: The key at this index is invalid, so we increment the index and try again\n");
        // Recursive call or loop to retry with incremented index
    }
	

    // Free OpenSSL big numbers
    BN_free(a);
    BN_free(parentKeyInt);
    BN_free(curveOrder);
    BN_free(newKey);
    BN_CTX_free(ctx);

	return info;
}
// -- Child key derivation --

// ++ ChildToAvaxpAddress ++

// ++ Bech32 Encode ++
__device__ void ConvertBytesTo5BitGroups(uint8_t *data, size_t len, int **result, size_t *result_len) {
    int buffer = 0;
    int bufferLength = 0;
    *result_len = 0;
    //*result = malloc(0);
    *result = (int *) malloc(0);

    for(size_t i = 0; i < len; i++) {
        uint8_t b = data[i];
        buffer = (buffer << 8) | b;
        bufferLength += 8;

        while(bufferLength >= 5) {
            *result_len += 1;
            //*result = realloc(*result, *result_len * sizeof(int));
            *result = (int *) realloc(*result, *result_len * sizeof(int));
            (*result)[*result_len - 1] = (buffer >> (bufferLength - 5)) & 31;
            bufferLength -= 5;
        }
    }

    if(bufferLength > 0) {
        *result_len += 1;
        //*result = realloc(*result, *result_len * sizeof(int));
        *result = (int *) realloc(*result, *result_len * sizeof(int));
        (*result)[*result_len - 1] = (buffer << (5 - bufferLength)) & 31;
    }
}

__device__ void ExpandHrp(const char *hrp, int *ret) {
    size_t hrp_len = strlen(hrp);
    for (size_t i = 0; i < hrp_len; ++i) {
        int c = hrp[i];
        ret[i] = c >> 5;
        ret[i + hrp_len + 1] = c & 31;
    }
    ret[hrp_len] = 0;
}

__device__ uint32_t PolyMod(int *values, size_t len) {
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

__device__ void CreateChecksum(const char *hrp, int *data, size_t data_len, int *checksum) {
    size_t hrp_len = strlen(hrp);
    //int *values = malloc((hrp_len * 2 + 1 + data_len + CHECKSUM_LENGTH) * sizeof(int));
    int *values = (int *) malloc((hrp_len * 2 + 1 + data_len + CHECKSUM_LENGTH) * sizeof(int));
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

__device__ char* Encode(const char *hrp, uint8_t *data, size_t data_len) {
    int *values, *checksum;
    size_t values_len;
    ConvertBytesTo5BitGroups(data, data_len, &values, &values_len);
    //checksum = malloc(CHECKSUM_LENGTH * sizeof(int));
    checksum = (int *) malloc(CHECKSUM_LENGTH * sizeof(int));

    CreateChecksum(hrp, values, values_len, checksum);

    size_t hrp_len = strlen(hrp);
    //char *result = malloc(hrp_len + 1 + values_len + CHECKSUM_LENGTH + 1);
    char *result = (char *) malloc(hrp_len + 1 + values_len + CHECKSUM_LENGTH + 1);

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

__device__ void hexStringToByteArray(const char *hexString, unsigned char *byteArray, int *byteArrayLength) {
    *byteArrayLength = strlen(hexString) / 2;
    printf("Expected length: %d\n", *byteArrayLength);  // Debug print
    for(int i = 0; i < *byteArrayLength; ++i) {
        sscanf(hexString + 2*i, "%2hhx", byteArray + i);
    }
}


__device__ void print_as_hex_char(unsigned char *data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

/*void computeSHA256(unsigned char *data, size_t len, unsigned char *hash) {
    SHA256(data, len, hash);
}*/

/*void compute_sha256(const uint8_t *msg, uint32_t mlen) {
    uint8_t md[MY_SHA256_DIGEST_LENGTH] = {0};  // Initialize to zero
    SHA256_CTX sha;
    SHA256_Init(&sha);

    SHA256_Update(&sha, msg, mlen);

    SHA256_Final(md, &sha);

    printf("Computed SHA-256: ");
    print_as_hex_uint(md, sizeof(md));
}*/

__device__ void compute_sha256(const uint8_t *msg, size_t mlen, uint8_t *outputHash) {
    SHA256_CTX sha;
    SHA256_Init(&sha);
    SHA256_Update(&sha, msg, mlen);
    SHA256_Final(outputHash, &sha);
}

__device__ void computeRIPEMD160(unsigned char *data, size_t len, unsigned char *hash) {
    RIPEMD160(data, len, hash);
}

/*char* bech32Encode(const char *hrp, unsigned char *data, size_t len) {
    // TODO: Implement this
    return NULL;
}*/

// Function to convert byte array to hexadecimal string
__device__ char* byteArrayToHexString(unsigned char *byteArray, size_t byteArrayLen) {
    //char *hexString = malloc(byteArrayLen * 2 + 1);  // Each byte becomes two hex characters; +1 for null-terminator
    char *hexString = (char *) malloc(byteArrayLen * 2 + 1);
    for (size_t i = 0; i < byteArrayLen; i++) {
        sprintf(hexString + i * 2, "%02x", byteArray[i]);
    }
    hexString[byteArrayLen * 2] = '\0';  // Null-terminate the string
    return hexString;
}

__device__ char* childToAvaxpAddress(const char *publicKeyHex) {
	printf("Input Public Key Hex: %s\n", publicKeyHex);
    printf("Expected Public Key Hex Length: %zu\n", strlen(publicKeyHex));
    int len;
    unsigned char publicKeyBytes[128];
    hexStringToByteArray(publicKeyHex, publicKeyBytes, &len);
    
    printf("Public Key: ");
    //print_as_hex_uint(publicKeyBytes, len);
    print_as_hex_uint(publicKeyBytes, (uint32_t) len);
    printf("Public Key Length: %d bytes\n", len);

    //unsigned char sha256Hash[SHA256_DIGEST_LENGTH];
	//unsigned char sha256Hash[MY_SHA256_DIGEST_LENGTH];
    //computeSHA256(publicKeyBytes, len, sha256Hash);
	//computeSHA256(publicKeyHex, len, sha256Hash);
	/*uint8_t sha256Hash[MY_SHA256_DIGEST_LENGTH];
    compute_sha256(publicKeyBytes, len);	
	printf("SHA256: ");
	print_as_hex_char(sha256Hash, MY_SHA256_DIGEST_LENGTH);*/
	uint8_t sha256Hash[MY_SHA256_DIGEST_LENGTH];
    //compute_sha256(publicKeyBytes, len, sha256Hash);
    compute_sha256(publicKeyBytes, (uint32_t) len, sha256Hash);

    printf("SHA256: ");
    print_as_hex_uint(sha256Hash, MY_SHA256_DIGEST_LENGTH);


    unsigned char ripemd160Hash[RIPEMD160_DIGEST_LENGTH];
    computeRIPEMD160(sha256Hash, MY_SHA256_DIGEST_LENGTH, ripemd160Hash);
	printf("RIPEMD160: ");
	print_as_hex_char(ripemd160Hash, RIPEMD160_DIGEST_LENGTH);

    //char *b32Encoded = bech32Encode("avax", ripemd160Hash, RIPEMD160_DIGEST_LENGTH);
	char *b32Encoded = Encode("avax", ripemd160Hash, RIPEMD160_DIGEST_LENGTH);

    //char *finalAddress = malloc(strlen(b32Encoded) + 3);
    char *finalAddress = (char *) malloc(strlen(b32Encoded) + 3);
    sprintf(finalAddress, "P-%s", b32Encoded);

    free(b32Encoded);
    return finalAddress;
}
// -- ChildToAvaxpAddress --
// -- pbdkf2 --

__device__ int string_compare(const char* str1, const char* str2, int length) {
    for (int i = 0; i < length; i++) {
        if (str1[i] != str2[i]) {
            return 0;
        }
    }
    return 1;
}

__global__ void my_kernel(
    char* mnemonic,
    char* computed_addresses,
    char* passphrases,
    char* target_addresses,
    unsigned char target_addresses_count,
    char* result
    ) 
    {
    int idx = threadIdx.x + blockIdx.x * blockDim.x;
    int LINE_LENGTH_ADDR = 45;
    int LINE_LENGTH_PASS = 10;
    int passphrase_idx = idx / 10;
    // Define the test_passphrase of length 10
    char test_passphrase[19]; //len('mnemonic') + len(passphrase)
    if (idx == 2309 && idx < 2310) {

        // print mnemonic
        printf("Cuda   salt: ");
        for (int i = 0; i < 156; i++) { // DOTO: Define your to mnemonic length
            printf("%c", mnemonic[i]);
        }
        printf("\n");
        
        // +++ Bip39SeedGenerator +++
        // add the "mnemonoic" text before the passphrase
        char mnemonic_word[9] = "mnemonic"; 
        for (int i = 0; i < 9; i++) {
            test_passphrase[i] = mnemonic_word[i];
        }
        // Fill the test_passphrase with the current passphrase
        for (int i = 0; i < LINE_LENGTH_PASS; i++) {
            test_passphrase[9+i] = passphrases[passphrase_idx * LINE_LENGTH_PASS + i];
        }        

        // print the test_passphrase
        printf("test_passphrase: ");
        for (int i = 0; i < LINE_LENGTH_PASS+9; i++) {
            printf("%c", test_passphrase[i]);
        }
        printf("\n");
        /*unsigned char* bip39seed = Bip39SeedGenerator();
        // print the bip39seed
        printf("bip39seed: ");
        for (int i = 0; i < 64; i++) {
            printf("%02X", bip39seed[i]);
        }
        printf("\n");*/
        unsigned char derived_key[64];  // This will hold the generated seed
        // Initialize derived_key to zeros
        for (int i = 0; i < 64; ++i) {
            derived_key[i] = 0;
        }
        //TODO: Update 19 for length of ur passphrase
        compute_pbkdf2(
            (uint8_t *) mnemonic, 
            strlen(mnemonic), 
            (uint8_t *) test_passphrase, 
            19, 
            ROUNDS, 
            DKLEN,
            derived_key
            );
        // --- Bip39SeedGenerator ---


        for (int target_idx = 0; target_idx < target_addresses_count; target_idx++) {
            // print string_compare(&computed_addresses[idx * LINE_LENGTH_ADDR]
            printf("&computed_addresses[idx * LINE_LENGTH_ADDR]: ");
            for (int i = 0; i < LINE_LENGTH_ADDR; i++) {
                printf("%c", computed_addresses[idx * LINE_LENGTH_ADDR + i]);
            }
            printf("\n");
            // Compare the computed address with the target address
            if (string_compare(&computed_addresses[idx * LINE_LENGTH_ADDR], &target_addresses[target_idx * LINE_LENGTH_ADDR], LINE_LENGTH_ADDR)) {
                // Print that match was found for idx, phrase, and target
                printf("Match found for idx %d, phrase %d, and target %d\n", idx, passphrase_idx, target_idx);
                for (int i = 0; i < LINE_LENGTH_PASS; i++) {
                    result[i] = passphrases[passphrase_idx * LINE_LENGTH_PASS + i];
                }
            }
        }
    }
}

/* ### Datatypes ###
Length (bytes) NumPy type	CUDA type
1 np.int8	    signed char 2**7-1 == 127
2 np.int16	    short 2**15-1 == 32767
4 np.int32	    int 2**31-1 == 2147483647
8 np.int64	    long long 2**63-1 == 9223372036854775807
1 np.uint8	    unsigned char 2**8-1 == 255
2 np.uint16	    unsigned short 2**16-1 == 65535
4 np.uint32     unsigned int 2**32-1 == 4294967295
8 np.uint64     unsigned long long 2**64-1 == 18446744073709551615
4 np.float32	float 2**32-1 == 4294967295
8 np.float64    double 2**64-1 == 18446744073709551615
*/