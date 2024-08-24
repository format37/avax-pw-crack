// BIP32 ++
typedef struct {
    unsigned char master_private_key[32];
    unsigned char chain_code[32];
    // unsigned char public_key[33];
} BIP32Info;

__device__ void my_cuda_memcpy_unsigned_char_b(uint8_t *dst, const uint8_t *src, unsigned int n) {
    for (unsigned int i = 0; i < n; ++i) {
        dst[i] = src[i];
    }
}

__device__ BIP32Info bip32_from_seed_kernel(const uint8_t *seed, uint32_t seed_len) {
    // printf("++ bip32_from_seed_kernel ++\n");
    // printf(">> seed: ");
    // print_as_hex(seed, seed_len);
    // printf(">> seed_len: %d\n", seed_len);

    BIP32Info info;
	// Initialize HMAC_SHA512_CTX
    HMAC_SHA512_CTX hmac;
    
    // Compute HMAC-SHA512 with "Bitcoin seed" as the key
    hmac_sha512_init(&hmac, (const uint8_t *)"Bitcoin seed", 12);
    hmac_sha512_update(&hmac, seed, seed_len);

    // Print hmac
    // printf("# hmac: ");
    
    unsigned char hash[64];
    // clear hash
    for (int i = 0; i < 64; ++i) {
        hash[i] = 0;
    }
    hmac_sha512_final(&hmac, hash);

    // // Print hash
    // printf("# hash: ");
    // print_as_hex(hash, 64);
    
    // Copy the first 32 bytes to master_private_key and the next 32 bytes to chain_code
    //my_cuda_memcpy_unsigned_char(info->master_private_key, hash, 32);
    //my_cuda_memcpy_unsigned_char(info->chain_code, hash + 32, 32);
	my_cuda_memcpy_unsigned_char_b(info.master_private_key, hash, 32);
	my_cuda_memcpy_unsigned_char_b(info.chain_code, hash + 32, 32);

    // printf("-- bip32_from_seed_kernel --\n");
	return info;
}
// BIP32 --