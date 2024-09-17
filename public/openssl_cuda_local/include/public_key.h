#define CURVE_P_VALUES_MAX_SIZE 4
__device__ __constant__ BN_ULONG CURVE_GX_values[CURVE_P_VALUES_MAX_SIZE] = {
        0x79BE667EF9DCBBAC,
        0x55A06295CE870B07,
        0x029BFCDB2DCE28D9,
        0x59F2815B16F81798
        };
__device__ __constant__ BN_ULONG CURVE_GY_values[CURVE_P_VALUES_MAX_SIZE] = {
        0x483ADA7726A3C465,
        0x5DA4FBFC0E1108A8,
        0xFD17B448A6855419,
        0x9C47D08FFB10D4B8
        };
__device__ __constant__ BIGNUM CURVE_A = {0};
__device__ __constant__ BIGNUM CURVE_P = {
    {
        0xFFFFFFFEFFFFFC2F,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF
    },
    CURVE_P_VALUES_MAX_SIZE,
    false
};

__device__ void GetPublicKey(uint8_t* buffer, uint8_t* key)
{
    BIGNUM newKey;
    init_zero(&newKey);
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
    newKey.top = CURVE_P_VALUES_MAX_SIZE;

    // Initialize generator
    EC_POINT G;
    init_zero(&G.x);
    init_zero(&G.y);
    for (int j = 0; j < MAX_BIGNUM_SIZE; ++j) {
            G.x.d[j] = CURVE_GX_values[j];
            G.y.d[j] = CURVE_GY_values[j];
        }
    // reverse
    reverse_order(&G.x, CURVE_P_VALUES_MAX_SIZE);
    reverse_order(&G.y, CURVE_P_VALUES_MAX_SIZE);
    G.x.top = CURVE_P_VALUES_MAX_SIZE;
    G.y.top = CURVE_P_VALUES_MAX_SIZE;

    // TODO: Check do we need to define curves, G and do reversing
    EC_POINT publicKey = ec_point_scalar_mul(&G, &newKey, &CURVE_P, &CURVE_A);    
    // Copy the public key to buffer
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
    // Shift the buffer by 1 byte
    for (int i = 33; i > 0; i--) {
        buffer[i] = buffer[i - 1];
    }
    
    // Determine the prefix based on the Y coordinate
    BIGNUM two, quotient, remainder;
    init_zero(&two);
    init_zero(&quotient);
    init_zero(&remainder);
    // Set two to 2
    bn_set_word(&two, 2);
    bn_div(&quotient, &remainder, &publicKey.y, &two);
    uint8_t prefix = bn_is_zero(&remainder) ? 0x02 : 0x03;
    // Add prefix before the buffer
    buffer[0] = prefix;
}