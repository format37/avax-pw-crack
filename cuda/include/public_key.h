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
    #ifdef function_profiler
        unsigned long long start_time = clock64();
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

    #ifdef use_montgomery_ec_point_multiplication
        // Make sure Montgomery context is initialized
        MONT_CTX_CUDA mont_ctx;
        if (!init_curve_montgomery_context(&CURVE_P, &CURVE_A, &mont_ctx)) {
            printf("Error: Failed to initialize Montgomery context\n");
            // Handle error case
            return;
        }
        // Generate public key using Montgomery scalar multiplication
        EC_POINT_CUDA publicKey;
        // init_point_at_infinity(&publicKey);
        ec_point_scalar_mul_montgomery(&G, &newKey, &mont_ctx, &publicKey);
    #else
        // TODO: Check do we need to define extra G. Or we are able to use __constant__ CURVE_GX_values and CURVE_GY_values as new EC_POINT_CUDA instead
        EC_POINT_CUDA publicKey = ec_point_scalar_mul(&G, &newKey, &CURVE_P, &CURVE_A); // FAIL with index 0. CHECK newKey.
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
    
    // Add prefix before the buffer
    buffer[0] = prefix;
    #ifdef function_profiler
        record_function(FN_GET_PUBLIC_KEY, start_time);
    #endif
}