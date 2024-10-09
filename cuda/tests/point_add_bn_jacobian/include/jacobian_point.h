struct EC_POINT_JACOBIAN {
    BIGNUM X;
    BIGNUM Y;
    BIGNUM Z;
};

__device__ void jacobian_point_double(
    EC_POINT_JACOBIAN *result,
    const EC_POINT_JACOBIAN *P,
    const BIGNUM *p,
    const BIGNUM *a
);

__device__ void bn_mod_sub(BIGNUM *result, const BIGNUM *a, const BIGNUM *b, const BIGNUM *n) {
    bn_sub(result, a, b);
    if (result->neg) {
        BIGNUM tmp;
        init_zero(&tmp);
        bn_copy(&tmp, result); // dest << src
        bn_add(result, &tmp, n); // result = a + b
        result->neg = 0;
    }
}

__device__ void bn_mod_add(BIGNUM *result, const BIGNUM *a, const BIGNUM *b, const BIGNUM *n) {
    bn_add(result, a, b);
    BIGNUM tmp;
    init_zero(&tmp);
    bn_copy(&tmp, result); // dest << src
    bn_mod(result, &tmp, n); // result = a mod n
}


#ifndef BN_128
    #define BN_UMULT_LOHI(h, l, a, b) \
    do { \
        BN_ULONG __a = (a), __b = (b); \
        BN_ULONG __r = __a * __b; \
        (h) = ((BN_ULONG)(__a) >> 32) * ((BN_ULONG)(__b) >> 32); \
        (l) = __r; \
    } while(0)
#endif

__device__ int bn_mul_word(BIGNUM *a, BN_ULONG w)
{
    BN_ULONG carry = 0;
    int i;

    for (i = 0; i < a->top; i++)
    {
        #ifdef BN_128
            unsigned __int128 res = (unsigned __int128)a->d[i] * w + carry;
            a->d[i] = (BN_ULONG)res;
            carry = (BN_ULONG)(res >> 128);
        #else
            BN_ULONG high, low;
            BN_UMULT_LOHI(high, low, a->d[i], w);
            low += carry;
            high += (low < carry);
            a->d[i] = low;
            carry = high;
        #endif
    }

    if (carry != 0)
    {
        if (a->top < MAX_BIGNUM_SIZE)
        {
            a->d[a->top++] = carry;
            return 1;
        }
        else
        {
            return 0; // Overflow
        }
    }

    a->top = find_top(a);
    return 1;
}

__device__ void affine_to_jacobian(const EC_POINT_CUDA *affine_point, EC_POINT_JACOBIAN *jacobian_point) {
    bn_copy(&jacobian_point->X, &affine_point->x);
    bn_copy(&jacobian_point->Y, &affine_point->y);
    init_one(&jacobian_point->Z); // Z = 1
}

__device__ void jacobian_to_affine(const EC_POINT_JACOBIAN *jacobian_point, EC_POINT_CUDA *affine_point, const BIGNUM *p) {
    if (bn_is_zero(&jacobian_point->Z)) {
        // Point at infinity
        set_point_at_infinity(affine_point);
        return;
    }

    BIGNUM Z_inv, Z_inv2, Z_inv3;

    init_zero(&Z_inv);
    init_zero(&Z_inv2);
    init_zero(&Z_inv3);

    // Compute Z_inv = Z^-1 mod p
    bn_mod_inverse(&Z_inv, &jacobian_point->Z, p);

    // Compute Z_inv2 = Z_inv^2 mod p
    bn_mul(&Z_inv, &Z_inv, &Z_inv2);
    bn_mod(&Z_inv2, &Z_inv2, p);

    // Compute Z_inv3 = Z_inv2 * Z_inv mod p
    bn_mul(&Z_inv2, &Z_inv, &Z_inv3);
    bn_mod(&Z_inv3, &Z_inv3, p);

    // x = X * Z_inv2 mod p
    bn_mul(&jacobian_point->X, &Z_inv2, &affine_point->x);
    bn_mod(&affine_point->x, &affine_point->x, p);

    // y = Y * Z_inv3 mod p
    bn_mul(&jacobian_point->Y, &Z_inv3, &affine_point->y);
    bn_mod(&affine_point->y, &affine_point->y, p);
}

__device__ void jacobian_point_add(
    EC_POINT_JACOBIAN *result,
    const EC_POINT_JACOBIAN *P,
    const EC_POINT_JACOBIAN *Q,
    const BIGNUM *p,
    const BIGNUM *a
) {
    // Handle special cases
    if (bn_is_zero(&P->Z)) {
        // P is at infinity, result = Q
        bn_copy(&result->X, &Q->X);
        bn_copy(&result->Y, &Q->Y);
        bn_copy(&result->Z, &Q->Z);
        return;
    }
    if (bn_is_zero(&Q->Z)) {
        // Q is at infinity, result = P
        bn_copy(&result->X, &P->X);
        bn_copy(&result->Y, &P->Y);
        bn_copy(&result->Z, &P->Z);
        return;
    }

    // Compute U1 = X1 * Z2^2 mod p
    BIGNUM Z2_squared, U1;
    init_zero(&Z2_squared);
    init_zero(&U1);
    bn_mul(&Q->Z, &Q->Z, &Z2_squared); // Z2^2
    bn_mod(&Z2_squared, &Z2_squared, p);
    bn_mul(&P->X, &Z2_squared, &U1);
    bn_mod(&U1, &U1, p);

    // Compute U2 = X2 * Z1^2 mod p
    BIGNUM Z1_squared, U2;
    init_zero(&Z1_squared);
    init_zero(&U2);
    bn_mul(&P->Z, &P->Z, &Z1_squared); // Z1^2
    bn_mod(&Z1_squared, &Z1_squared, p);
    bn_mul(&Q->X, &Z1_squared, &U2);
    bn_mod(&U2, &U2, p);

    // Compute S1 = Y1 * Z2^3 mod p
    BIGNUM Z2_cubed, S1;
    init_zero(&Z2_cubed);
    init_zero(&S1);
    bn_mul(&Z2_squared, &Q->Z, &Z2_cubed); // Z2^3
    bn_mod(&Z2_cubed, &Z2_cubed, p);
    bn_mul(&P->Y, &Z2_cubed, &S1);
    bn_mod(&S1, &S1, p);

    // Compute S2 = Y2 * Z1^3 mod p
    BIGNUM Z1_cubed, S2;
    init_zero(&Z1_cubed);
    init_zero(&S2);
    bn_mul(&Z1_squared, &P->Z, &Z1_cubed); // Z1^3
    bn_mod(&Z1_cubed, &Z1_cubed, p);
    bn_mul(&Q->Y, &Z1_cubed, &S2);
    bn_mod(&S2, &S2, p);

    // Now compute H = U2 - U1 mod p
    BIGNUM H;
    init_zero(&H);
    bn_mod_sub(&H, &U2, &U1, p);

    // r = S2 - S1 mod p
    BIGNUM r;
    init_zero(&r);
    bn_mod_sub(&r, &S2, &S1, p);

    // Check if H == 0
    if (bn_is_zero(&H)) {
        if (bn_is_zero(&r)) {
            // P == Q, perform doubling
            jacobian_point_double(result, P, p, a);
            return;
        } else {
            // P == -Q, result is point at infinity
            init_zero(&result->X);
            init_zero(&result->Y);
            init_zero(&result->Z); // Z = 0 represents point at infinity
            return;
        }
    }

    // Compute H^2, H^3, U1*H^2
    BIGNUM H_squared, H_cubed, U1_H_squared;
    init_zero(&H_squared);
    init_zero(&H_cubed);
    init_zero(&U1_H_squared);

    bn_mul(&H, &H, &H_squared); // H^2
    bn_mod(&H_squared, &H_squared, p);

    bn_mul(&H_squared, &H, &H_cubed); // H^3
    bn_mod(&H_cubed, &H_cubed, p);

    bn_mul(&U1, &H_squared, &U1_H_squared); // U1 * H^2
    bn_mod(&U1_H_squared, &U1_H_squared, p);

    // Compute r^2
    BIGNUM r_squared;
    init_zero(&r_squared);
    bn_mul(&r, &r, &r_squared);
    bn_mod(&r_squared, &r_squared, p);

    // X3 = r^2 - H^3 - 2 * U1_H_squared mod p
    BIGNUM two_U1_H_squared;
    init_zero(&two_U1_H_squared);
    bn_mod_add(&two_U1_H_squared, &U1_H_squared, &U1_H_squared, p);

    BIGNUM temp;
    init_zero(&temp);
    bn_mod_sub(&temp, &r_squared, &H_cubed, p);
    bn_mod_sub(&temp, &temp, &two_U1_H_squared, p);
    bn_copy(&result->X, &temp);

    // Y3 = r * (U1_H_squared - X3) - S1 * H^3 mod p
    BIGNUM U1_H_squared_minus_X3;
    init_zero(&U1_H_squared_minus_X3);
    bn_mod_sub(&U1_H_squared_minus_X3, &U1_H_squared, &result->X, p);

    BIGNUM r_times_U1_H_squared_minus_X3;
    init_zero(&r_times_U1_H_squared_minus_X3);
    bn_mul(&r, &U1_H_squared_minus_X3, &r_times_U1_H_squared_minus_X3);
    bn_mod(&r_times_U1_H_squared_minus_X3, &r_times_U1_H_squared_minus_X3, p);

    BIGNUM S1_H_cubed;
    init_zero(&S1_H_cubed);
    bn_mul(&S1, &H_cubed, &S1_H_cubed);
    bn_mod(&S1_H_cubed, &S1_H_cubed, p);

    bn_mod_sub(&result->Y, &r_times_U1_H_squared_minus_X3, &S1_H_cubed, p);

    // Z3 = H * Z1 * Z2 mod p
    bn_mul(&P->Z, &Q->Z, &result->Z);
    bn_mod(&result->Z, &result->Z, p);
    bn_mul(&result->Z, &H, &result->Z);
    bn_mod(&result->Z, &result->Z, p);

    // Print results
    bn_print_no_fuse("point_add << X: ", &result->X);
    bn_print_no_fuse("point_add << Y: ", &result->Y);
    bn_print_no_fuse("point_add << Z: ", &result->Z);
}

__device__ void jacobian_point_double(
    EC_POINT_JACOBIAN *result,
    const EC_POINT_JACOBIAN *P,
    const BIGNUM *p,
    const BIGNUM *a
) {
    if (bn_is_zero(&P->Z) || bn_is_zero(&P->Y)) {
        // Point at infinity
        init_zero(&result->X);
        init_zero(&result->Y);
        init_zero(&result->Z);
        return;
    }

    BIGNUM XX, YY, YYYY, ZZ, S, M, T;
    init_zero(&XX);
    init_zero(&YY);
    init_zero(&YYYY);
    init_zero(&ZZ);
    init_zero(&S);
    init_zero(&M);
    init_zero(&T);

    // XX = X1^2 mod p
    bn_mul(&P->X, &P->X, &XX);
    bn_mod(&XX, &XX, p);

    // YY = Y1^2 mod p
    bn_mul(&P->Y, &P->Y, &YY);
    bn_mod(&YY, &YY, p);

    // YYYY = YY^2 mod p
    bn_mul(&YY, &YY, &YYYY);
    bn_mod(&YYYY, &YYYY, p);

    // ZZ = Z1^2 mod p
    bn_mul(&P->Z, &P->Z, &ZZ);
    bn_mod(&ZZ, &ZZ, p);

    // S = 4 * X1 * YY mod p
    bn_mul(&P->X, &YY, &S);
    bn_mod(&S, &S, p);
    bn_mul_word(&S, 4);
    bn_mod(&S, &S, p);

    // M = 3 * XX + a * ZZ^2 mod p
    BIGNUM aZZ_squared;
    init_zero(&aZZ_squared);
    bn_mul(&ZZ, &ZZ, &aZZ_squared);
    bn_mul(&aZZ_squared, a, &aZZ_squared);
    bn_mod(&aZZ_squared, &aZZ_squared, p);

    bn_mul_word(&XX, 3);
    bn_mod_add(&M, &XX, &aZZ_squared, p);

    // X3 = M^2 - 2 * S mod p
    bn_mul(&M, &M, &T);
    bn_mod(&T, &T, p);
    BIGNUM two_S;
    init_zero(&two_S);
    bn_mod_add(&two_S, &S, &S, p);
    bn_mod_sub(&result->X, &T, &two_S, p);

    // Y3 = M * (S - X3) - 8 * YYYY mod p
    BIGNUM S_minus_X3;
    init_zero(&S_minus_X3);
    bn_mod_sub(&S_minus_X3, &S, &result->X, p);

    bn_mul(&M, &S_minus_X3, &result->Y);
    bn_mod(&result->Y, &result->Y, p);

    BIGNUM eight_YYYY;
    init_zero(&eight_YYYY);
    bn_mul_word(&YYYY, 8);
    bn_mod(&eight_YYYY, &eight_YYYY, p);

    bn_mod_sub(&result->Y, &result->Y, &eight_YYYY, p);

    // Z3 = 2 * Y1 * Z1 mod p
    bn_mul(&P->Y, &P->Z, &result->Z);
    bn_mul_word(&result->Z, 2);
    bn_mod(&result->Z, &result->Z, p);

    // Print results
    bn_print_no_fuse("point_double << X: ", &result->X);
    bn_print_no_fuse("point_double << Y: ", &result->Y);
    bn_print_no_fuse("point_double << Z: ", &result->Z);
}

__device__ EC_POINT_CUDA ec_point_scalar_mul_jacobian(
    EC_POINT_CUDA *point, 
    BIGNUM *scalar, 
    BIGNUM *curve_prime, 
    BIGNUM *curve_a
) {
    EC_POINT_JACOBIAN current, result;
    affine_to_jacobian(point, &current);
    init_zero(&result.X);
    init_zero(&result.Y);
    init_zero(&result.Z);
    init_one(&result.Z); // Initialize result as point at infinity in Jacobian coordinates (Z=0)

    unsigned int bits[256];
    bignum_to_bit_array(scalar, bits);

    for (int i = 255; i >= 0; i--) {
        // Point doubling
        jacobian_point_double(&result, &result, curve_prime, curve_a);

        if (bits[i]) {
            // Point addition
            jacobian_point_add(&result, &result, &current, curve_prime, curve_a);
        }
    }

    // Convert result back to affine coordinates
    EC_POINT_CUDA affine_result;
    jacobian_to_affine(&result, &affine_result, curve_prime);

    return affine_result;
}