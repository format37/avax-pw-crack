#ifdef BN_128
    #define CURVE_P_VALUES_MAX_SIZE 2

    __device__ __constant__ BN_ULONG CURVE_GX_values[CURVE_P_VALUES_MAX_SIZE] = {
        0x029BFCDB2DCE28D959F2815B16F81798,
        0x79BE667EF9DCBBAC55A06295CE870B07
    };

    __device__ __constant__ BN_ULONG CURVE_GY_values[CURVE_P_VALUES_MAX_SIZE] = {
        0xFD17B448A68554199C47D08FFB10D4B8,
        0x483ADA7726A3C4655DA4FBFC0E1108A8
    };

    __device__ __constant__ BIGNUM_CUDA CURVE_A = {0};

    __device__ __constant__ BIGNUM_CUDA CURVE_P = {
        {
            0xfffffffffffffffffffffffefffffc2f,
            0xffffffffffffffffffffffffffffffff
        },
        CURVE_P_VALUES_MAX_SIZE,
        false
    };
#else
    #define CURVE_P_VALUES_MAX_SIZE 4
    __device__ __constant__ BN_ULONG CURVE_GX_values[CURVE_P_VALUES_MAX_SIZE] = {
            0x59F2815B16F81798,
            0x029BFCDB2DCE28D9,
            0x55A06295CE870B07,
            0x79BE667EF9DCBBAC
            };
    __device__ __constant__ BN_ULONG CURVE_GY_values[CURVE_P_VALUES_MAX_SIZE] = {
            0x9C47D08FFB10D4B8,
            0xFD17B448A6855419,
            0x5DA4FBFC0E1108A8,
            0x483ADA7726A3C465
            };
    __device__ __constant__ BIGNUM_CUDA CURVE_A = {0};
    __device__ __constant__ BIGNUM_CUDA CURVE_P = {
        {
            0xFFFFFFFEFFFFFC2F,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF
        },
        CURVE_P_VALUES_MAX_SIZE,
        false
    };
#endif

__device__ void GetPublicKey(uint8_t* buffer, uint8_t* key)
{
    #ifdef debug_print
        printf("++ GetPublicKey ++\n");
        // print key
        printf(">> key: ");
        for (int i = 0; i < 32; i++) {
            printf("%02x", key[i]);
        }
        printf("\n");
    #endif
    BIGNUM_CUDA newKey;
    init_zero(&newKey);
    #ifdef BN_128
        for (int i = 0; i < CURVE_P_VALUES_MAX_SIZE; ++i) {
            newKey.d[CURVE_P_VALUES_MAX_SIZE - 1 - i] = ((BN_ULONG)key[16*i] << 120) |
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
    #else
        for (int i = 0; i < CURVE_P_VALUES_MAX_SIZE; ++i) {
            newKey.d[3 - i] = ((BN_ULONG)key[8*i] << 56) | 
                                ((BN_ULONG)key[8*i + 1] << 48) | 
                                ((BN_ULONG)key[8*i + 2] << 40) | 
                                ((BN_ULONG)key[8*i + 3] << 32) |
                                ((BN_ULONG)key[8*i + 4] << 24) | 
                                ((BN_ULONG)key[8*i + 5] << 16) | 
                                ((BN_ULONG)key[8*i + 6] << 8) | 
                                ((BN_ULONG)key[8*i + 7]);
        }
    #endif
    newKey.top = CURVE_P_VALUES_MAX_SIZE;

    #ifdef debug_print
        // Print newKey
        bn_print("[#] newKey: ", &newKey);
    #endif

    // Initialize generator
    EC_POINT_CUDA G;
    init_zero(&G.x);
    init_zero(&G.y);
    // for (int j = 0; j < MAX_BIGNUM_SIZE; ++j) {
    for (int j = 0; j < CURVE_P_VALUES_MAX_SIZE; ++j) {
            G.x.d[j] = CURVE_GX_values[j];
            G.y.d[j] = CURVE_GY_values[j];
        }
    G.x.top = CURVE_P_VALUES_MAX_SIZE;
    G.y.top = CURVE_P_VALUES_MAX_SIZE;
    #ifdef debug_top
        if (G.x.top != find_top(&G.x)) printf("### ERROR: GetPublicKey: G.x.top (%d) != find_top(&G.x) (%d)\n", G.x.top, find_top(&G.x));
        if (G.y.top != find_top(&G.y)) printf("### ERROR: GetPublicKey: G.y.top (%d) != find_top(&G.y) (%d)\n", G.y.top, find_top(&G.y));
    #endif

    // TODO: Check do we need to define extra G. Or we are able to use __constant__ CURVE_GX_values and CURVE_GY_values as new EC_POINT_CUDA instead
    EC_POINT_CUDA publicKey = ec_point_scalar_mul(&G, &newKey, &CURVE_P, &CURVE_A); // FAIL with index 0. CHECK newKey.
    #ifdef debug_print
        // Print the public key
        bn_print("[*] publicKey.x: ", &publicKey.x);
        bn_print("[*] publicKey.y: ", &publicKey.y);
    #endif

    
    // Copy the public key to buffer
    #ifdef BN_128
        // Copy the public key to buffer for 128-bit
        for (int i = 0; i < CURVE_P_VALUES_MAX_SIZE; i++) {
            BN_ULONG word = publicKey.x.d[CURVE_P_VALUES_MAX_SIZE - 1 - i];
            for (int j = 0; j < 16; j++) {
                buffer[16*i + j] = (word >> (120 - 8*j)) & 0xFF;
            }
        }
    #else
        for (int i = 0; i < CURVE_P_VALUES_MAX_SIZE; i++) {
            buffer[8*i] = (publicKey.x.d[3 - i] >> 56) & 0xFF;
            buffer[8*i + 1] = (publicKey.x.d[3 - i] >> 48) & 0xFF;
            buffer[8*i + 2] = (publicKey.x.d[3 - i] >> 40) & 0xFF;
            buffer[8*i + 3] = (publicKey.x.d[3 - i] >> 32) & 0xFF;
            buffer[8*i + 4] = (publicKey.x.d[3 - i] >> 24) & 0xFF;
            buffer[8*i + 5] = (publicKey.x.d[3 - i] >> 16) & 0xFF;
            buffer[8*i + 6] = (publicKey.x.d[3 - i] >> 8) & 0xFF;
            buffer[8*i + 7] = publicKey.x.d[3 - i] & 0xFF;
        }
    #endif
    // Shift the buffer by 1 byte
    for (int i = 33; i > 0; i--) {
        buffer[i] = buffer[i - 1];
    }
    
    // Determine the prefix based on the Y coordinate
    BIGNUM_CUDA two, quotient, remainder;
    init_zero(&two);
    init_zero(&quotient);
    init_zero(&remainder);
    // Set two to 2
    bn_set_word(&two, 2);
    bn_div(&quotient, &remainder, &publicKey.y, &two);
    uint8_t prefix = bn_is_zero(&remainder) ? 0x02 : 0x03;
    
    // Alternate solution of copying the public key to buffer
    // Is not so clear as the previous one but works for both 64-bit and 128-bit
    // // Copy the public key to buffer
    // size_t limb_size_bytes = sizeof(BN_ULONG);
    // for (int i = 0; i < CURVE_P_VALUES_MAX_SIZE; i++) {
    //     BN_ULONG limb = publicKey.x.d[CURVE_P_VALUES_MAX_SIZE - 1 - i];
    //     for (int j = 0; j < limb_size_bytes; j++) {
    //         buffer[limb_size_bytes * i + j + 1] = (limb >> (8 * (limb_size_bytes - 1 - j))) & 0xFF;
    //     }
    // }
    
    // Add prefix before the buffer
    buffer[0] = prefix;
    #ifdef debug_print
        // Print the public key
        printf(">> buffer: ");
        for (int i = 0; i < 33; i++) {
            printf("%02x", buffer[i]);
        }
        printf("\n-- GetPublicKey --\n");
    #endif
}