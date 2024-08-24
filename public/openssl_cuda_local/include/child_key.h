// Child key derivation ++
__device__ void my_cuda_memcpy_uint32_t(uint32_t *dst, const uint32_t *src, unsigned int n) {
    for (unsigned int i = 0; i < n / sizeof(uint32_t); ++i) {
        uint32_t val = src[i];
        dst[i] = __byte_perm(val, 0, 0x0123);
    }
}

__device__ void my_cuda_memcpy_uint32_t_to_unsigned_char(unsigned char *dst, const uint32_t *src, unsigned int n) {
    for (unsigned int i = 0; i < n / sizeof(uint32_t); ++i) {
        uint32_t val = src[i];
        dst[4 * i] = (val) & 0xFF;
        dst[4 * i + 1] = (val >> 8) & 0xFF;
        dst[4 * i + 2] = (val >> 16) & 0xFF;
        dst[4 * i + 3] = (val >> 24) & 0xFF;
    }
}

__device__ BIP32Info GetChildKeyDerivation(uint8_t* key, uint8_t* chainCode, uint32_t index, uint8_t prefix) {
	// printf("++ GetChildKeyDerivation ++\n");
    // printf(">> key: ");
    // print_as_hex(key, 32);
    // printf(">> chainCode: ");
    // print_as_hex(chainCode, 32);
    // printf(">> index: %u\n", index);
    // printf("\n* step 0 index: %u\n", index);
    BIP32Info info;

    // Compute HMAC-SHA512
    HMAC_SHA512_CTX hmac;
    uint8_t buffer[100];
    uint8_t hash[64];
    // unsigned int len = 64;

    // Fill buffer according to index
    if (index == 0) {
		// printf("    * INDEX is 0\n");
        GetPublicKey(buffer, key, prefix);

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
    // printf("      * Cuda Pre-HMAC variable key:");
    // for (int i = 0; i < 32; i++) {
    //     printf("%02x", key[i]);
    // }
    // printf("\n");

    // printf("      * Cuda Pre-HMAC Buffer:");
    // for (int i = 0; i < 37; i++) { // Assuming the buffer length up to the index is 37
    //     printf("%02x", buffer[i]);
    // }
    // printf("\n");

    // printf("      * Cuda Pre-HMAC Key:");
    // for (int i = 0; i < 32; i++) {
    //     printf("%02x", chainCode[i]);
    // }
    // printf("\n");   

	uint32_t il[8], ir[8];
	
	// Populate il and ir from hash
	my_cuda_memcpy_uint32_t(il, (uint32_t*)hash, 8 * sizeof(uint32_t)); // Using uint32_t version for il
	my_cuda_memcpy_uint32_t(ir, (uint32_t*)(hash + 32), 8 * sizeof(uint32_t)); // Using uint32_t version for ir

    // // Print the hash from 32 to 64
    // printf("      * Cuda hash from 32 to 64:");
    // for (int i = 32; i < 64; i++) {
    //     printf("%02x", hash[i]);
    // }
    // printf("\n");

    // Copy the hash (from 32 to 64) to chain_code
    my_cuda_memcpy_unsigned_char(info.chain_code, hash + 32, 32);

	// // After HMAC-SHA512
	// printf("      * Cuda Post-HMAC hash:");
	// for (int i = 0; i < 64; i++) {
	// 	printf("%02x", hash[i]);
	// }
	// printf("\n");

	// printf("      * Cuda il as uint32_t: ");
	// for (int i = 0; i < 8; ++i) {
	// 	printf("%08x", il[i]);
	// }
	// printf("\n");

	// printf("      * Cuda ir as uint32_t: ");
	// for (int i = 0; i < 8; ++i) {
	// 	printf("%08x", ir[i]);
	// }
	// printf("\n");

    // printf("      * Cuda ir as uint64_t: ");
    uint64_t ir_64[4];
    for (int i = 0; i < 8; ++i) {
        ir_64[i] = ((uint64_t)ir[2*i] << 32) | (uint64_t)ir[2*i + 1];
    }
    // for (int i = 0; i < 4; ++i) {
    //     printf("%016lx", ir_64[i]);
    // }
    // printf("\n");

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

	// // Print individual bytes of chain_code after copying
	// printf("      * Individual bytes of Cuda chain_code after copying: ");
	// for (int i = 0; i < 32; ++i) {
	// 	printf("%02x", info.chain_code[i]);
	// }
	// printf("\n");

	// // After populating il and ir
	// printf("    * il: ");
	// for (int i = 0; i < 8; i++) {
	// 	printf("%08x", il[i]);
	// }
	// printf("\n");
	// printf("    * ir: ");
	// for (int i = 0; i < 8; i++) {
	// 	printf("%08x", ir[i]);
	// }
	// printf("\n");    
	
	// Addition
	BIGNUM a;
	BIGNUM b;
	BIGNUM curveOrder;
	BIGNUM newKey;
	BIGNUM publicKey;

    init_zero(&a);
    init_zero(&b);
    init_zero(&curveOrder);
    init_zero(&newKey);
    init_zero(&publicKey);

	// BN_ULONG a_d[8];
  	// BN_ULONG b_d[8];
	BN_ULONG newKey_d[8];
  	// BN_ULONG curveOrder_d[16];
	// BN_ULONG publicKey_d[8];
	// uint32_t curveOrder[8] = {0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe, 0xbaaedce6, 0xaf48a03b, 0xbfd25e8c, 0xd0364141};
	// Initialize curveOrder_d for secp256k1
	// FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    // 
    curveOrder.d[0] = 0xBFD25E8CD0364141;
    curveOrder.d[1] = 0xBAAEDCE6AF48A03B;
    curveOrder.d[2] = 0xFFFFFFFFFFFFFFFE;
    curveOrder.d[3] = 0xFFFFFFFFFFFFFFFF;
    curveOrder.neg = 0;
    curveOrder.top = 4;
    
    // hash: uint8_t[64]
    // il: uint32_t il[8]
    // a.d: is BN_ULONG
    // Initialize a from il
    for (int i = 0; i < 4; ++i) {
        a.d[3 - i] = ((BN_ULONG)il[2*i] << 32) | (BN_ULONG)il[2*i + 1];
    }
    a.neg = 0;
    a.top = 4;  // We're using 4 64-bit words
    // bn_print("A: ", &a);

	// key: uint8_t*
    // b.d: BN_ULONG
    // Initialize b from key
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
    // bn_print("B: ", &b);

    // return info;

	// Initialize newKey_d
	for (int i = 0; i < 8; i++) newKey_d[i] = 0;
	// newKey.d = newKey_d;
    for (int j = 0; j < 8; ++j) {
        newKey.d[j] = newKey_d[j]; // TODO: Check do we need to reverse the order
    }
	newKey.neg = 0;
	// newKey.top = 8;
    newKey.top = find_top(&newKey);
    // bn_print("Debug Cuda newKey (Before add): ", &newKey);
	
    bn_add(&newKey, &a, &b);

    // // Print A + B
    // bn_print("Debug Cuda newKey (After add): ", &newKey);

    // // Print curve order
    // bn_print("Debug Cuda curveOrder: ", &curveOrder);

    // printf("Calling bn_mod\n");
    bn_mod(&newKey, &newKey, &curveOrder);

    // printf("After bn_mod\n");
    // bn_print("Debug Cuda newKey (After mod): ", &newKey);

    // Copy newKey to info.master_private_key
    for (int i = 0; i < 4; i++) {
        info.master_private_key[8*i] = (newKey.d[3 - i] >> 56) & 0xFF;
        info.master_private_key[8*i + 1] = (newKey.d[3 - i] >> 48) & 0xFF;
        info.master_private_key[8*i + 2] = (newKey.d[3 - i] >> 40) & 0xFF;
        info.master_private_key[8*i + 3] = (newKey.d[3 - i] >> 32) & 0xFF;
        info.master_private_key[8*i + 4] = (newKey.d[3 - i] >> 24) & 0xFF;
        info.master_private_key[8*i + 5] = (newKey.d[3 - i] >> 16) & 0xFF;
        info.master_private_key[8*i + 6] = (newKey.d[3 - i] >> 8) & 0xFF;
        info.master_private_key[8*i + 7] = newKey.d[3 - i] & 0xFF;
    }
	
    // printf("\n");
    return info;
}
