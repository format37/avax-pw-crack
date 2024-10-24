#define MY_SHA256_DIGEST_LENGTH 32
#define CHARSET "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
#define CHECKSUM_LENGTH 6
#define DKLEN 64
#define ROUNDS 2048

void print_as_hex_char(unsigned char *data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Debug print for OpenSSL BIGNUM in Hexadecimal
void print_bn_hex(const char* label, const BIGNUM* bn) {
    char* bn_str = BN_bn2hex(bn);
    #ifdef debug_print
        printf("%s (Hexadecimal): %s\n", label, bn_str);
    #endif
    OPENSSL_free(bn_str);
}

void my_cuda_memcpy_unsigned_char(uint8_t *dst, const uint8_t *src, unsigned int n) {
    for (unsigned int i = 0; i < n; ++i) {
        dst[i] = src[i];
    }
}

void print_as_hex_uint(const uint8_t *data,  const uint32_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

std::vector<unsigned char> generate_seed(const std::string& mnemonic, const std::string& passphrase) {
    std::string salt = "mnemonic" + passphrase;
    std::vector<unsigned char> seed(64);

    PKCS5_PBKDF2_HMAC(mnemonic.c_str(), mnemonic.length(),
                      reinterpret_cast<const unsigned char*>(salt.c_str()), salt.length(),
                      2048, EVP_sha512(),
                      64, seed.data());

    return seed;
}

std::string bytes_to_hex(const std::vector<unsigned char>& bytes) {
    std::string hex;
    for (unsigned char byte : bytes) {
        char hex_byte[3];
        snprintf(hex_byte, sizeof(hex_byte), "%02x", byte);
        hex += hex_byte;
    }
    return hex;
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
    #ifdef debug_print
        // Print input values
        printf("++ PBKDF2 ++\n");
        printf(">> key: %s\n", key);
        printf(">> klen: %u\n", klen);
        printf(">> salt: %s\n", salt);
        printf(">> slen: %u\n", slen);
        printf(">> rounds: %u\n", rounds);
        printf(">> dklen: %u\n", dklen);
        // derived_key
        printf(">> derived_key: ");
        for(int i = 0; i < dklen; i++) {
            printf("%02x", derived_key[i]);
        }
        printf("\n");
    #endif
    if (klen > INT_MAX || slen > INT_MAX || rounds > INT_MAX || dklen > INT_MAX) {
        // Handle error, perhaps return a specific error code or print an error message.
        printf("Error: klen, slen, rounds, or dklen is too large\n");
        #ifdef debug_print
            printf("-- PBKDF2 --\n");
        #endif
        return;
    }
    uint8_t *dk = new uint8_t[dklen];

    if (dk == NULL) {
        // Handle memory allocation failure
        fprintf(stderr, "Memory allocation failed\n");
        #ifdef debug_print
            printf("-- PBKDF2 --\n");
        #endif
        exit(1);
    }
    // Check if uint32_t values can fit into int
    if (klen > INT_MAX || slen > INT_MAX || rounds > INT_MAX || dklen > INT_MAX) {
        // Handle error: these values are too large to be safely cast to int
        fprintf(stderr, "One of the uint32_t values is too large to fit into an int.\n");
        #ifdef debug_print
            printf("-- PBKDF2 --\n");
        #endif
        exit(1);  // Or other error handling
    }
    
    std::string mnemonic;
    // Set mnemonic from salt
    mnemonic = (const char *)key;
    std::string passphrase;
    // Set passphrase from key
    passphrase = (const char *)salt;
    std::vector<unsigned char> seed = generate_seed(mnemonic, passphrase);
    #ifdef debug_print
        std::cout << "* Seed: " << bytes_to_hex(seed) << std::endl;
    #endif
    // Set dk_values to seed
    std::copy(seed.begin(), seed.end(), dk);

	#ifdef debug_print
        printf("Computed PBKDF2-SHA-512: ");
        print_as_hex_uint(dk, dklen);
    #endif
	my_cuda_memcpy_unsigned_char(derived_key, dk, dklen);
	
    delete[] dk;
    #ifdef debug_print
        printf("-- PBKDF2 --\n");
    #endif
}
// -- SHA --

// ++ bip32 From seed ++
typedef struct {
    unsigned char master_private_key[32];
    unsigned char chain_code[32];
} BIP32Info;

BIP32Info bip32_from_seed(const uint8_t *seed, uint32_t seed_len)
{
    #ifdef debug_print
        printf("Seed length: %d\n", seed_len);
    #endif
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
// Debug print for OpenSSL BIGNUM
void print_bn(const char* label, const BIGNUM* bn) {
	char* bn_str = BN_bn2dec(bn);
	printf("%s: %s\n", label, bn_str);
	OPENSSL_free(bn_str);
}

unsigned char *GetPublicKey(unsigned char *privateKeyBytes, size_t privateKeyLen, size_t *publicKeyLen) {
    EC_GROUP *curve = NULL;
    EC_KEY *eckey = NULL;
    BIGNUM *privateKey = NULL;
    EC_POINT *pub_key = NULL;
    unsigned char *publicKeyBytes = NULL;
    
    curve = EC_GROUP_new_by_curve_name(NID_secp256k1);
    // print all curve parameters
    #ifdef debug_print
        printf("Curve parameters:\n");
    #endif
    
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

    int nid = EC_GROUP_get_curve_name(curve);
    if (nid != NID_undef) {
        const char *curve_name = OBJ_nid2sn(nid);
        printf("Curve NID: %d, Name: %s\n", nid, curve_name);
    } else {
        printf("Curve does not have a NID.\n");
    }

    EC_KEY_set_public_key(eckey, pub_key);

    *publicKeyLen = EC_POINT_point2oct(EC_KEY_get0_group(eckey), EC_KEY_get0_public_key(eckey), POINT_CONVERSION_COMPRESSED, NULL, 0, NULL);
    
    // Replace by new[]
    publicKeyBytes = new unsigned char[(size_t) *publicKeyLen];

    if (publicKeyBytes == NULL) {
        return NULL;
    }
    EC_POINT_point2oct(EC_KEY_get0_group(eckey), EC_KEY_get0_public_key(eckey), POINT_CONVERSION_COMPRESSED, publicKeyBytes, (size_t) *publicKeyLen, NULL);
    
    EC_GROUP_free(curve);
    EC_KEY_free(eckey);
    EC_POINT_free(pub_key);
    BN_free(privateKey);

    return publicKeyBytes;
}

BIP32Info GetChildKeyDerivation(uint8_t* key, uint8_t* chainCode, uint32_t index) {
	static int chain_counter = 0;
    // static char path[100] = ""; // Assuming path length won't exceed 100
    static std::string path = ""; // Use std::string


    #ifdef debug_print
        printf("\n* step %d index: %u\n", chain_counter, index);
        // Print the full derivation path
        printf("  * chain path: %s\n", path);
    #endif
    chain_counter++; // Increment the counter for the next step

    // BigEndianBuffer equivalent
    uint8_t buffer[100]; // Assuming buffer length won't exceed 100
    size_t buffer_len = 0;

    if (index == 0) {
		#ifdef debug_print
            printf("    * INDEX is 0\n");
        #endif
		size_t publicKeyLen = 0;
		unsigned char *publicKeyBytes = GetPublicKey(key, 32, &publicKeyLen);
		#ifdef debug_print
            print_as_hex_char(publicKeyBytes, publicKeyLen);
        #endif
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

    #ifdef debug_print
        // Display debug information
        printf("      * C Pre-HMAC variable key:");
        print_as_hex_char(key, 32);
        printf("      * C Pre-HMAC Buffer:");
        print_as_hex_char(buffer, buffer_len);
        printf("      * C Pre-HMAC Key:");
        print_as_hex_char(chainCode, 32);
    #endif

	// Slice the hash into 'il' and 'ir'
    uint8_t il[32], ir[32];
    memcpy(il, hash, 32);
    memcpy(ir, hash + 32, 32);

    // After HMAC-SHA512
    #ifdef debug_print
        printf("      * C Post-HMAC hash:");
        print_as_hex_char(hash, 64);
        printf("\n");
    #endif

    uint32_t *il_32 = (uint32_t *)il;
    uint32_t *ir_32 = (uint32_t *)ir;

    #ifdef debug_print
        printf("      * C il as uint32_t: ");
        for (int i = 0; i < 8; ++i) {
            printf("%08x", il_32[i]);
        }
        printf("\n");

        printf("      * C ir as uint32_t: ");
        for (int i = 0; i < 8; ++i) {
            printf("%08x", ir_32[i]);
        }
        printf("\n");

        // Print 'il' and 'ir'
        printf("    * il: ");
        print_as_hex_char(il, 32);
        printf("    * ir: ");
        print_as_hex_char(ir, 32);
    #endif

	// Initialize OpenSSL big numbers
    BIGNUM *a = BN_new();
    BIGNUM *parentKeyInt = BN_new();
    BIGNUM *curveOrder = BN_new();
    BN_CTX *ctx = BN_CTX_new();

	// Set curve order for secp256k1
	BN_dec2bn(&curveOrder, "115792089237316195423570985008687907852837564279074904382605163141518161494337");

    #ifdef debug_print
        print_bn_hex("Curve Order", curveOrder);
    #endif

	// Convert byte arrays to big numbers
	BN_bin2bn(il, 32, a);
	BN_bin2bn(key, 32, parentKeyInt);

	#ifdef debug_print
        // Debug prints before BN_mod_add
        print_bn("Debug C a (Before mod_add)", a);
        print_bn_hex("Debug C a (Before mod_add)", a);
        print_bn("Debug C parentKeyInt (Before mod_add)", parentKeyInt);
        print_bn_hex("Debug C parentKeyInt (Before mod_add)", parentKeyInt);
    #endif

	// Intermediate manual addition
	BIGNUM *tempSum = BN_new();
	BN_add(tempSum, a, parentKeyInt);

    unsigned char my_buffer[64];
    BN_bn2bin(tempSum, my_buffer);
    #ifdef debug_print
        printf("Debug C Intermediate Sums (Hexadecimal):\n");
        for (int i = 0; i < BN_num_bytes(tempSum); i+=4) {
            uint32_t val = *((uint32_t*)(&my_buffer[i]));
            printf("At index %d: val = %x\n", i / 4, val);
        }

        print_bn("Debug C Temp Sum (a + parentKeyInt)", tempSum);
        print_bn_hex("Debug C Temp Sum (a + parentKeyInt)", tempSum);
    #endif
    
	BN_free(tempSum);

    BIGNUM *newKey = BN_new();

	// Perform BN_mod_add
	if (BN_mod_add(newKey, a, parentKeyInt, curveOrder, ctx) != 1) {
		printf("Error in BN_mod_add\n");
	}

	// Debug print after BN_mod_add
	#ifdef debug_print
        print_bn("Debug C newKey (After mod_add)", newKey);
    #endif

	BIP32Info info;
	int cmpResult = BN_cmp(a, curveOrder);
	if (cmpResult < 0 && !BN_is_zero(newKey)) {
		uint8_t newKeyBytes[32] = {0};  // Initialize to zero

		// Debugging: Print length before conversion
		int newKeyLen = 0;
		#ifdef debug_print
            printf("newKeyLen before BN_bn2bin: %d\n", newKeyLen);

            // Convert newKey to byte array
            print_bn("Debug C newKey (Before BN_bn2bin)", newKey);
        #endif
		newKeyLen = BN_bn2bin(newKey, newKeyBytes);
		#ifdef debug_print
            print_bn("Debug C newKey (After BN_bn2bin)", newKey);

            // Debugging: Print length and hex dump after conversion
            printf("newKeyLen after BN_bn2bin: %d\n", newKeyLen);
            printf("newKeyBytes before reverse: ");
            print_as_hex_char(newKeyBytes, newKeyLen);

            // Debugging: Print hex dump after reverse
            printf("newKeyBytes after reverse: ");
            print_as_hex_char(newKeyBytes, newKeyLen);
            
            // Output newKeyBytes and ir (ChainCode)
            printf("  * chain code:");
            print_as_hex_char(ir, 32);
            // print chain code as uint32_t array
            printf("  * chain code as uint32_t array: ");
            for (int i = 0; i < 8; ++i) {
                printf("%08x-", ir_32[i]);
            }
            printf("\n");
            printf("  * private:");
            print_as_hex_char(newKeyBytes, 32);
            // print private key as uint32_t array
            printf("  * private key as uint32_t array: ");
            for (int i = 0; i < 8; ++i) {
                printf("%08x-", newKeyBytes[i]);
            }
            printf("\n");
            printf("  * public:");
        #endif
		
        size_t publicKeyLen = 0;
		unsigned char *publicKeyBytes = GetPublicKey(newKeyBytes, 32, &publicKeyLen);
		
        #ifdef debug_print
            print_as_hex_char(publicKeyBytes, publicKeyLen);
            // print public key as uint32_t array
            printf("  * public key as uint32_t array: ");
            for (int i = 0; i < 8; ++i) {
                printf("%08x-", publicKeyBytes[i]);
            }
            printf("\n");
        #endif

        // Add the current index to the path
        char index_str[12];  // Assuming index won't exceed 10 digits
        sprintf(index_str, "%u", index);
        // strcat(path, "/");
        // strcat(path, index_str);
        path += "/"; // Use += for string concatenation
        path += index_str;

        #ifdef debug_print
            // Print the full derivation path
            printf("  * chain path: %s\n", path);
        #endif

		memcpy(info.master_private_key, newKeyBytes, 32);
		memcpy(info.chain_code, ir, 32);

        // If newKeyBytes is less than 32 bytes, you'll need to pad with zeros at the beginning.
        // If it's more than 32 bytes, you'll need to truncate. This can be done here.
    } else {
        #ifdef debug_print
            printf("C GetChildKeyDerivation: The key at this index is invalid, so we increment the index and try again\n");
        #endif
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
template<typename T>
T* safe_realloc(T* ptr, size_t new_size) {
    T* new_ptr = static_cast<T*>(realloc(ptr, new_size * sizeof(T)));
    if (!new_ptr && new_size != 0) {
        // Handle reallocation failure
        delete[] ptr;
        throw std::bad_alloc();  // or handle the error in another way
    }
    return new_ptr;
}

void ConvertBytesTo5BitGroups(uint8_t *data, size_t len, int **result, size_t *result_len) {
    int buffer = 0;
    int bufferLength = 0;
    *result_len = 0;
    // Don't initialize *result here; it's handled by safe_realloc
    
    for(size_t i = 0; i < len; i++) {
        uint8_t b = data[i];
        buffer = (buffer << 8) | b;
        bufferLength += 8;

        while(bufferLength >= 5) {
            *result_len += 1;
            // *result = realloc(*result, *result_len * sizeof(int));
            *result = safe_realloc(*result, *result_len);
            

            (*result)[*result_len - 1] = (buffer >> (bufferLength - 5)) & 31;
            bufferLength -= 5;
        }
    }
    if(bufferLength > 0) {
        *result_len += 1;
        *result = safe_realloc(*result, *result_len);
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
    int *values = new int[hrp_len * 2 + 1 + data_len + CHECKSUM_LENGTH];
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

    delete[] values;
}

char* Encode(const char *hrp, uint8_t *data, size_t data_len) {
    int *values = nullptr; // Initialize to nullptr
    size_t values_len;
    ConvertBytesTo5BitGroups(data, data_len, &values, &values_len); // values is now allocated

    int *checksum = new int[CHECKSUM_LENGTH];

    // checksum = new int[CHECKSUM_LENGTH];
    CreateChecksum(hrp, values, values_len, checksum);

    size_t hrp_len = strlen(hrp);
    char *result = new char[hrp_len + 1 + values_len + CHECKSUM_LENGTH + 1];
    strcpy(result, hrp);
    strcat(result, "1");

    for (size_t i = 0; i < values_len; ++i) {
        result[hrp_len + 1 + i] = CHARSET[values[i]];
    }
    for (size_t i = 0; i < CHECKSUM_LENGTH; ++i) {
        result[hrp_len + 1 + values_len + i] = CHARSET[checksum[i]];
    }
    result[hrp_len + 1 + values_len + CHECKSUM_LENGTH] = '\0';

    delete[] values;
    delete[] checksum;

    return result;
}
// -- Bech32 Encode --

void hexStringToByteArray(const char *hexString, unsigned char *byteArray, int *byteArrayLength) {
    *byteArrayLength = strlen(hexString) / 2;
    #ifdef debug_print
        printf("Expected length: %d\n", *byteArrayLength);  // Debug print
    #endif    
    for(int i = 0; i < *byteArrayLength; ++i) {
        sscanf(hexString + 2*i, "%2hhx", byteArray + i);
    }
}

void compute_sha256(const uint8_t *msg, size_t mlen, uint8_t *outputHash) {
    // print mlen
    #ifdef debug_print
        printf(" _### mlen ###_: %zu\n", mlen);
    #endif
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
    char *hexString = new char[byteArrayLen * 2 + 1];  // Each byte becomes two hex characters; +1 for null-terminator
    for (size_t i = 0; i < byteArrayLen; i++) {
        sprintf(hexString + i * 2, "%02x", byteArray[i]);
    }
    hexString[byteArrayLen * 2] = '\0';  // Null-terminate the string
    return hexString;
}

char* childToAvaxpAddress(const char *publicKeyHex) {
	#ifdef debug_print
        printf("Input Public Key Hex: %s\n", publicKeyHex);
        printf("Expected Public Key Hex Length: %zu\n", strlen(publicKeyHex));
    #endif
    int len;
    unsigned char publicKeyBytes[128];
    hexStringToByteArray(publicKeyHex, publicKeyBytes, &len);
    #ifdef debug_print
        printf("Public Key: ");
        print_as_hex_uint(publicKeyBytes, (uint32_t) len);
        printf("Public Key Length: %d bytes\n", len);
    #endif
	uint8_t sha256Hash[MY_SHA256_DIGEST_LENGTH];
    compute_sha256(publicKeyBytes, (uint32_t) len, sha256Hash);

    #ifdef debug_print
        printf("SHA256: ");
        print_as_hex_uint(sha256Hash, MY_SHA256_DIGEST_LENGTH);
    #endif


    unsigned char ripemd160Hash[RIPEMD160_DIGEST_LENGTH];
    computeRIPEMD160(sha256Hash, MY_SHA256_DIGEST_LENGTH, ripemd160Hash);
	#ifdef debug_print
        printf("RIPEMD160: ");
        print_as_hex_char(ripemd160Hash, RIPEMD160_DIGEST_LENGTH);
    #endif

	char *b32Encoded = Encode("avax", ripemd160Hash, RIPEMD160_DIGEST_LENGTH);

    char *finalAddress = new char[strlen(b32Encoded) + 3];
    sprintf(finalAddress, "P-%s", b32Encoded);

    delete[] b32Encoded;
    return finalAddress;
}
// -- ChildToAvaxpAddress --

// int EC_POINT_mul_alter(const EC_GROUP *group, EC_POINT *r, const BIGNUM *g_scalar,
//                  const EC_POINT *point, const BIGNUM *p_scalar, BN_CTX *ctx)
// {
//     printf("++ EC_POINT_mul ++\n");
//     int ret = 0;
//     size_t num;
// // #ifndef FIPS_MODULE
//     BN_CTX *new_ctx = NULL;
// // #endif

//     if (!ec_point_is_compat(r, group)
//         || (point != NULL && !ec_point_is_compat(point, group))) {
//         ERR_raise(ERR_LIB_EC, EC_R_INCOMPATIBLE_OBJECTS);
//         return 0;
//     }

//     if (g_scalar == NULL && p_scalar == NULL)
//         return EC_POINT_set_to_infinity(group, r);

// // #ifndef FIPS_MODULE
//     if (ctx == NULL)
//         ctx = new_ctx = BN_CTX_secure_new();
// // #endif
//     if (ctx == NULL) {
//         // ERR_raise(ERR_LIB_EC, ERR_R_INTERNAL_ERROR);
//         return 0;
//     }

//     num = (point != NULL && p_scalar != NULL) ? 1 : 0;
//     if (group->meth->mul != NULL) {
//             printf("EC_POINT_mul: group->meth->mul\n");
//             // ret = group->meth->mul(group, r, g_scalar, num, &point, &p_scalar, ctx);
//         }
//     else {
//             /* use default */
//             printf("EC_POINT_mul: ossl_ec_wNAF_mul\n");
//             // ret = ossl_ec_wNAF_mul(group, r, g_scalar, num, &point, &p_scalar, ctx);
//         }

// #ifndef FIPS_MODULE
//     BN_CTX_free(new_ctx);
// #endif
//     printf("-- EC_POINT_mul --\n");
//     return ret;
// }