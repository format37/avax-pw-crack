struct EC_POINT_CUDA {
  BIGNUM_CUDA x; 
  BIGNUM_CUDA y;
};

struct EC_POINT_JACOBIAN {
    BIGNUM_CUDA X;
    BIGNUM_CUDA Y;
    BIGNUM_CUDA Z;
};

__device__ bool bn_mod_inverse(BIGNUM_CUDA *result, const BIGNUM_CUDA *a, const BIGNUM_CUDA *n);
__device__ void bignum_to_bit_array(BIGNUM_CUDA *n, unsigned int *bits);
__device__ int point_is_at_infinity(const EC_POINT_CUDA *P);
__device__ void bn_mod_lshift1(BIGNUM_CUDA *r, const BIGNUM_CUDA *a, const BIGNUM_CUDA *n); // point.h

__device__ void print_jacobian_point(const char* label, const EC_POINT_JACOBIAN *point) {
    printf("%s:\n", label);
    bn_print_no_fuse("  X: ", &point->X);
    bn_print_no_fuse("  Y: ", &point->Y);
    bn_print_no_fuse("  Z: ", &point->Z);
}

__device__ void set_point_at_infinity(EC_POINT_CUDA *point) {
    // Assuming EC_POINT_CUDA is a structure containing BIGNUM_CUDA x and y
    // and that a BIGNUM_CUDA value of NULL or {0} represents the point at infinity

    // To set the point at infinity, one straightforward way is to assign
    // a null pointer to x and y if the BIGNUM_CUDA structure allows it, or 
    // set their values to some predetermined sentinel value that indicates
    // the point at infinity.

    // If using the sentinel value approach - ensure BIGNUM_CUDA is set in a way
    // that other functions can check for it and treat it as infinity

    // To set the point to 0 (as an example sentinel value), do:
    init_zero(&point->x);
    init_zero(&point->y);// Ensure that this logic matches how you identify point at infinity elsewhere
}

__device__ void jacobian_point_double(
    EC_POINT_JACOBIAN *result,
    const EC_POINT_JACOBIAN *P,
    const BIGNUM_CUDA *p,
    const BIGNUM_CUDA *a
) {
    if (bn_is_zero(&P->Z) || bn_is_zero(&P->Y)) {
        init_zero(&result->X);
        init_zero(&result->Y);
        init_zero(&result->Z);
        return;
    }

    BIGNUM_CUDA T1, T2, T3, T4, T5, T6;
    init_zero(&T1);
    init_zero(&T2);
    init_zero(&T3);
    init_zero(&T4);
    init_zero(&T5);
    init_zero(&T6);

    // T1 = X1^2
    bn_mod_sqr(&T1, &P->X, p);

    // T2 = 3 * T1
    BIGNUM_CUDA three;
    init_zero(&three);
    bn_set_word(&three, 3);
    bn_mod_mul(&T2, &T1, &three, p);

    // T3 = Y1^2
    bn_mod_sqr(&T3, &P->Y, p);

    // T4 = T3^2
    bn_mod_sqr(&T4, &T3, p);

    // T5 = X1 * T3
    bn_mod_mul(&T5, &P->X, &T3, p);

    // T5 = 2 * T5
    bn_mod_lshift1(&T5, &T5, p);

    // X3 = T2^2 - 2 * T5
    bn_mod_sqr(&T6, &T2, p);
    BIGNUM_CUDA temp;
    init_zero(&temp);
    bn_mod_lshift1(&temp, &T5, p);
    bn_mod_sub(&result->X, &T6, &temp, p);

    // Y3 = T2 * (T5 - X3) - 8 * T4
    bn_mod_sub(&T6, &T5, &result->X, p);
    bn_mod_mul(&T6, &T2, &T6, p);
    bn_mod_lshift(&T4, &T4, 3, p); // 8 * T4
    bn_mod_sub(&result->Y, &T6, &T4, p);

    // Z3 = 2 * Y1 * Z1
    bn_mod_mul(&T6, &P->Y, &P->Z, p);
    bn_mod_lshift1(&result->Z, &T6, p);
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

__device__ void affine_to_jacobian(const EC_POINT_CUDA *affine_point, EC_POINT_JACOBIAN *jacobian_point) {
    if (point_is_at_infinity(affine_point)) {
        // Point at infinity in Jacobian coordinates is represented by Z = 0
        init_zero(&jacobian_point->X);
        init_zero(&jacobian_point->Y);
        init_zero(&jacobian_point->Z); // Z = 0
    } else {
        bn_copy(&jacobian_point->X, &affine_point->x);
        bn_copy(&jacobian_point->Y, &affine_point->y);
        init_one(&jacobian_point->Z); // Z = 1
    }
}

__device__ void jacobian_to_affine(const EC_POINT_JACOBIAN *jacobian_point, EC_POINT_CUDA *affine_point, const BIGNUM_CUDA *p) {
    if (bn_is_zero(&jacobian_point->Z)) {
        // Point at infinity
        set_point_at_infinity(affine_point);
        return;
    }

    BIGNUM_CUDA Z_inv, Z_inv2, Z_inv3;

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

__device__ void point_add_jacobian(
    EC_POINT_JACOBIAN *result,
    const EC_POINT_JACOBIAN *P,
    const EC_POINT_JACOBIAN *Q,
    const BIGNUM_CUDA *p,
    const BIGNUM_CUDA *a
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
    BIGNUM_CUDA Z2_squared, U1;
    init_zero(&Z2_squared);
    init_zero(&U1);
    bn_mul(&Q->Z, &Q->Z, &Z2_squared); // Z2^2
    bn_mod(&Z2_squared, &Z2_squared, p);
    bn_mul(&P->X, &Z2_squared, &U1);
    bn_mod(&U1, &U1, p);

    // Compute U2 = X2 * Z1^2 mod p
    BIGNUM_CUDA Z1_squared, U2;
    init_zero(&Z1_squared);
    init_zero(&U2);
    bn_mul(&P->Z, &P->Z, &Z1_squared); // Z1^2
    bn_mod(&Z1_squared, &Z1_squared, p);
    bn_mul(&Q->X, &Z1_squared, &U2);
    bn_mod(&U2, &U2, p);

    // Compute S1 = Y1 * Z2^3 mod p
    BIGNUM_CUDA Z2_cubed, S1;
    init_zero(&Z2_cubed);
    init_zero(&S1);
    bn_mul(&Z2_squared, &Q->Z, &Z2_cubed); // Z2^3
    bn_mod(&Z2_cubed, &Z2_cubed, p);
    bn_mul(&P->Y, &Z2_cubed, &S1);
    bn_mod(&S1, &S1, p);

    // Compute S2 = Y2 * Z1^3 mod p
    BIGNUM_CUDA Z1_cubed, S2;
    init_zero(&Z1_cubed);
    init_zero(&S2);
    bn_mul(&Z1_squared, &P->Z, &Z1_cubed); // Z1^3
    bn_mod(&Z1_cubed, &Z1_cubed, p);
    bn_mul(&Q->Y, &Z1_cubed, &S2);
    bn_mod(&S2, &S2, p);

    // Now compute H = U2 - U1 mod p
    BIGNUM_CUDA H;
    init_zero(&H);
    bn_mod_sub(&H, &U2, &U1, p);

    // r = S2 - S1 mod p
    BIGNUM_CUDA r;
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
    BIGNUM_CUDA H_squared, H_cubed, U1_H_squared;
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
    BIGNUM_CUDA r_squared;
    init_zero(&r_squared);
    bn_mul(&r, &r, &r_squared);
    bn_mod(&r_squared, &r_squared, p);

    // X3 = r^2 - H^3 - 2 * U1_H_squared mod p
    BIGNUM_CUDA two_U1_H_squared;
    init_zero(&two_U1_H_squared);
    bn_mod_add(&two_U1_H_squared, &U1_H_squared, &U1_H_squared, p);

    BIGNUM_CUDA temp;
    init_zero(&temp);
    bn_mod_sub(&temp, &r_squared, &H_cubed, p);
    bn_mod_sub(&temp, &temp, &two_U1_H_squared, p);
    bn_copy(&result->X, &temp);

    // Y3 = r * (U1_H_squared - X3) - S1 * H^3 mod p
    BIGNUM_CUDA U1_H_squared_minus_X3;
    init_zero(&U1_H_squared_minus_X3);
    bn_mod_sub(&U1_H_squared_minus_X3, &U1_H_squared, &result->X, p);

    BIGNUM_CUDA r_times_U1_H_squared_minus_X3;
    init_zero(&r_times_U1_H_squared_minus_X3);
    bn_mul(&r, &U1_H_squared_minus_X3, &r_times_U1_H_squared_minus_X3);
    bn_mod(&r_times_U1_H_squared_minus_X3, &r_times_U1_H_squared_minus_X3, p);

    BIGNUM_CUDA S1_H_cubed;
    init_zero(&S1_H_cubed);
    bn_mul(&S1, &H_cubed, &S1_H_cubed);
    bn_mod(&S1_H_cubed, &S1_H_cubed, p);

    bn_mod_sub(&result->Y, &r_times_U1_H_squared_minus_X3, &S1_H_cubed, p);

    
    // Z3 = H * Z1 * Z2 mod p
    bn_mul(&P->Z, &Q->Z, &result->Z); // a * b = product
    
    bn_copy(&temp, &result->Z); // dest << src
    bn_mod(&result->Z, &temp, p); // result = a % m
    
    bn_copy(&temp, &result->Z); // dest << src
    bn_mul(&temp, &H, &result->Z); // a * b = product

    bn_copy(&temp, &result->Z); // dest << src
    bn_mod(&result->Z, &temp, p); // result = a % m
}

__device__ void copy_jacobian_point(EC_POINT_JACOBIAN *dest, const EC_POINT_JACOBIAN *src) {
    bn_copy(&dest->X, &src->X);
    bn_copy(&dest->Y, &src->Y);
    bn_copy(&dest->Z, &src->Z);
}