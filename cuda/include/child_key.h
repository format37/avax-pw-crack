// Initialize curveOrder_d for secp256k1
// FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
#ifdef BN_128
    #define CURVE_ORDER_SIZE 2
    __device__ __constant__ BIGNUM_CUDA CURVE_ORDER = {
        {
            0xBAAEDCE6AF48A03BBFD25E8CD0364141,
            0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE
        },
        CURVE_ORDER_SIZE,
        false
    };
#else
    #define CURVE_ORDER_SIZE 4
    __device__ __constant__ BIGNUM_CUDA CURVE_ORDER = {
        {
            0xBFD25E8CD0364141,
            0xBAAEDCE6AF48A03B,
            0xFFFFFFFFFFFFFFFE,
            0xFFFFFFFFFFFFFFFF
        },
        CURVE_ORDER_SIZE,
        false
    };
#endif

// Child key derivation ++
__device__ void my_cuda_memcpy_uint32_t(uint32_t *dst, const uint32_t *src, unsigned int n) {
    for (unsigned int i = 0; i < n / sizeof(uint32_t); ++i) {
        uint32_t val = src[i];
        dst[i] = __byte_perm(val, 0, 0x0123);
    }
}

__device__ BIP32Info GetChildKeyDerivation(uint8_t* key, uint8_t* chainCode, uint32_t index) {
	#ifdef function_profiler
        unsigned long long start_time = clock64();
    #endif
    #ifdef debug_print
        printf("++ GetChildKeyDerivation ++\n");
        printf(">> key: ");
        print_as_hex(key, 32);
        printf(">> chainCode: ");
        print_as_hex(chainCode, 32);
        printf(">> index: %u\n", index);
    #endif
    BIP32Info info;

    // Compute HMAC-SHA512
    HMAC_SHA512_CTX hmac;
    uint8_t buffer[100];
    uint8_t hash[64];

    // Fill buffer according to index
    if (index == 0) {
        #ifdef debug_print
		    printf("child_key.h => GetPublicKey\n");
        #endif
        GetPublicKey(buffer, key);

    } else {
        buffer[0] = 0;
        my_cuda_memcpy_unsigned_char(buffer + 1, key, 32);
    }

    // Append index in big-endian format to buffer
    buffer[33] = (index >> 24) & 0xFF;
    buffer[34] = (index >> 16) & 0xFF;
    buffer[35] = (index >> 8) & 0xFF;
    buffer[36] = index & 0xFF;

	hmac_sha512_init(&hmac, chainCode, 32);
    hmac_sha512_update(&hmac, buffer, 37);  // Assuming buffer_len = 37 // TODO: Check would it be defined in "int len"? 64
    hmac_sha512_final(&hmac, hash);

	// Print the pre-HMAC values
    #ifdef debug_print
        printf("      * Cuda Pre-HMAC variable key:");
        for (int i = 0; i < 32; i++) {
            printf("%02x", key[i]);
        }
        printf("\n");

        printf("      * Cuda Pre-HMAC Buffer:");
        for (int i = 0; i < 37; i++) { // Assuming the buffer length up to the index is 37
            printf("%02x", buffer[i]);
        }
        printf("\n");

        printf("      * Cuda Pre-HMAC Key:");
        for (int i = 0; i < 32; i++) {
            printf("%02x", chainCode[i]);
        }
        printf("\n");   
    #endif

	uint32_t il[8], ir[8];
	
	// Populate il and ir from hash
	my_cuda_memcpy_uint32_t(il, (uint32_t*)hash, 8 * sizeof(uint32_t)); // Using uint32_t version for il
	my_cuda_memcpy_uint32_t(ir, (uint32_t*)(hash + 32), 8 * sizeof(uint32_t)); // Using uint32_t version for ir

    #ifdef debug_print
        // Print the hash from 32 to 64
        printf("      * Cuda hash from 32 to 64:");
        for (int i = 32; i < 64; i++) {
            printf("%02x", hash[i]);
        }
        printf("\n");
    #endif

    // Copy the hash (from 32 to 64) to chain_code
    my_cuda_memcpy_unsigned_char(info.chain_code, hash + 32, 32);

	// After HMAC-SHA512
    #ifdef debug_print
        printf("      * Cuda Post-HMAC hash:");
        for (int i = 0; i < 64; i++) {
            printf("%02x", hash[i]);
        }
        printf("\n");

        printf("      * Cuda il as uint32_t: ");
        for (int i = 0; i < 8; ++i) {
            printf("%08x", il[i]);
        }
        printf("\n");

        printf("      * Cuda ir as uint32_t: ");
        for (int i = 0; i < 8; ++i) {
            printf("%08x", ir[i]);
        }
        printf("\n");

        printf("      * Cuda ir as uint64_t: ");
    #endif
    uint64_t ir_64[4];
    for (int i = 0; i < 8; ++i) {
        ir_64[i] = ((uint64_t)ir[2*i] << 32) | (uint64_t)ir[2*i + 1];
    }
    #ifdef debug_print
        for (int i = 0; i < 4; ++i) {
            printf("%016lx", ir_64[i]);
        }
        printf("\n");
    #endif

	// Perform the copy
    // Copy ir_64 to chain_code
    for (int i = 0; i < 4; i++) {
        info.chain_code[8*i] = (ir_64[i] >> 56) & 0xFF;
        info.chain_code[8*i + 1] = (ir_64[i] >> 48) & 0xFF;
        info.chain_code[8*i + 2] = (ir_64[i] >> 40) & 0xFF;
        info.chain_code[8*i + 3] = (ir_64[i] >> 32) & 0xFF;
        info.chain_code[8*i + 4] = (ir_64[i] >> 24) & 0xFF;
        info.chain_code[8*i + 5] = (ir_64[i] >> 16) & 0xFF;
        info.chain_code[8*i + 6] = (ir_64[i] >> 8) & 0xFF;
        info.chain_code[8*i + 7] = ir_64[i] & 0xFF;
    }

	#ifdef debug_print
        // Print individual bytes of chain_code after copying
        printf("      * Individual bytes of Cuda chain_code after copying: ");
        for (int i = 0; i < 32; ++i) {
            printf("%02x", info.chain_code[i]);
        }
        printf("\n");

        // After populating il and ir
        printf("    * il: ");
        for (int i = 0; i < 8; i++) {
            printf("%08x", il[i]);
        }
        printf("\n");
        printf("    * ir: ");
        for (int i = 0; i < 8; i++) {
            printf("%08x", ir[i]);
        }
        printf("\n");
    #endif
	
	// Addition
	BIGNUM_CUDA a;
	BIGNUM_CUDA b;
	// BIGNUM_CUDA curveOrder;
	BIGNUM_CUDA newKey;
	BIGNUM_CUDA publicKey;

    init_zero(&a);
    init_zero(&b);
    // init_zero(&curveOrder);
    init_zero(&newKey);
    init_zero(&publicKey);
    
    // hash: uint8_t[64]
    // il: uint32_t il[8]
    // a.d: is BN_ULONG
    // Initialize a from il
    #ifdef BN_128
        for (int i = 0; i < 2; ++i) {
            a.d[1 - i] = ((BN_ULONG)il[4*i] << 96) |
                        ((BN_ULONG)il[4*i + 1] << 64) |
                        ((BN_ULONG)il[4*i + 2] << 32) |
                        (BN_ULONG)il[4*i + 3];
        }
        a.neg = 0;
        a.top = 2;  // We're using 2 128-bit words
    #else
        for (int i = 0; i < 4; ++i) {
            a.d[3 - i] = ((BN_ULONG)il[2*i] << 32) | (BN_ULONG)il[2*i + 1];
        }
        a.neg = 0;
        a.top = 4;  // We're using 4 64-bit words
    #endif
    bn_print("A: ", &a);

	// key: uint8_t*
    // b.d: BN_ULONG
    // Initialize b from key
    #ifdef BN_128
        for (int i = 0; i < 2; ++i) {
            b.d[1 - i] = ((BN_ULONG)key[16*i] << 120) |
                        ((BN_ULONG)key[16*i + 1] << 112) |
                        ((BN_ULONG)key[16*i + 2] << 104) |
                        ((BN_ULONG)key[16*i + 3] << 96) |
                        ((BN_ULONG)key[16*i + 4] << 88) |
                        ((BN_ULONG)key[16*i + 5] << 80) |
                        ((BN_ULONG)key[16*i + 6] << 72) |
                        ((BN_ULONG)key[16*i + 7] << 64) |
                        ((BN_ULONG)key[16*i + 8] << 56) |
                        ((BN_ULONG)key[16*i + 9] << 48) |
                        ((BN_ULONG)key[16*i + 10] << 40) |
                        ((BN_ULONG)key[16*i + 11] << 32) |
                        ((BN_ULONG)key[16*i + 12] << 24) |
                        ((BN_ULONG)key[16*i + 13] << 16) |
                        ((BN_ULONG)key[16*i + 14] << 8) |
                        (BN_ULONG)key[16*i + 15];
        }
        b.neg = 0;
        b.top = 2;  // We're using 2 128-bit words
    #else
        for (int i = 0; i < 4; ++i) {
            b.d[3 - i] = ((BN_ULONG)key[8*i] << 56) | 
                        ((BN_ULONG)key[8*i + 1] << 48) | 
                        ((BN_ULONG)key[8*i + 2] << 40) | 
                        ((BN_ULONG)key[8*i + 3] << 32) |
                        ((BN_ULONG)key[8*i + 4] << 24) | 
                        ((BN_ULONG)key[8*i + 5] << 16) | 
                        ((BN_ULONG)key[8*i + 6] << 8) | 
                        ((BN_ULONG)key[8*i + 7]);
        }
        b.neg = 0;
        b.top = 4;  // We're using 4 64-bit words
    #endif
    #ifdef debug_print
        bn_print("B: ", &b);
        
        bn_print("Debug Cuda newKey (Before add): ", &newKey);
    #endif
	
    bn_add(&newKey, &a, &b);

    #ifdef debug_print
        // Print A + B
        bn_print("Debug Cuda newKey (After add): ", &newKey);

        // Print curve order
        bn_print("Debug Cuda curveOrder: ", &CURVE_ORDER);
        printf("Calling bn_mod\n");
    #endif
    bn_mod(&newKey, &newKey, &CURVE_ORDER);

    #ifdef debug_print
        printf("After bn_mod\n");
        bn_print("Debug Cuda newKey (After mod): ", &newKey);
    #endif    

    #ifdef BN_128
        // 128-bit case
        for (int i = 0; i < 2; i++) {
            for (int j = 0; j < 16; j++) {
                info.master_private_key[16*i + j] = (newKey.d[1 - i] >> (120 - 8*j)) & 0xFF;
            }
        }
    #else
        // 64-bit case
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 8; j++) {
                info.master_private_key[8*i + j] = (newKey.d[3 - i] >> (56 - 8*j)) & 0xFF;
            }
        }
    #endif
	
    // Print master private key
    #ifdef debug_print
        printf("<< info.master_private_key: ");
        for (int i = 0; i < 32; i++) {
            printf("%02x", info.master_private_key[i]);
        }
        printf("\n");
        printf("-- GetChildKeyDerivation --\n");    
    #endif
    #ifdef function_profiler
        record_function(FN_GET_CHILD_KEY_DERIVATION, start_time);
    #endif
    return info;
}
