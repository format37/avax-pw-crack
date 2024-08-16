// Jacobian point structure
typedef struct {
    BIGNUM X;
    BIGNUM Y;
    BIGNUM Z;
} JacobianPoint;

// Function to check if a point is at infinity
__device__ int is_point_at_infinity(JacobianPoint *P) {
    return bn_is_zero(&P->Z);
}

// Function to set a point to infinity
__device__ void set_point_to_infinity(JacobianPoint *P) {
    bn_set_word(&P->X, 1);
    bn_set_word(&P->Y, 1);
    bn_set_word(&P->Z, 0);
}

// Jacobian point doubling: R = 2*P
__device__ void jacobian_point_double(JacobianPoint *R, JacobianPoint *P, BIGNUM *p) {
    if (is_point_at_infinity(P)) {
        set_point_to_infinity(R);
        return;
    }

    BIGNUM A, B, C, D, mod_tmp;
    init_zero(&A);
    init_zero(&B);
    init_zero(&C);
    init_zero(&D);

    // A = X1^2
    bn_mul(&P->X, &P->X, &A);
    // bn_mod(&A, p, &A); // fix with mod_tmp
    init_zero(&mod_tmp);
    bn_mod(&mod_tmp, &A, p);
    bn_copy(&A, &mod_tmp);

    // B = Y1^2
    bn_mul(&P->Y, &P->Y, &B);
    // bn_mod(&B, p, &B); // fix with mod_tmp
    init_zero(&mod_tmp);
    bn_mod(&mod_tmp, &B, p);
    bn_copy(&B, &mod_tmp);

    // C = B^2
    bn_mul(&B, &B, &C);
    // bn_mod(&C, p, &C); // fix with mod_tmp
    init_zero(&mod_tmp);
    bn_mod(&mod_tmp, &C, p);
    bn_copy(&C, &mod_tmp);

    // D = 2*((X1+B)^2 - A - C)
    BIGNUM temp;
    init_zero(&temp);
    bn_add(&P->X, &B, &temp);
    bn_mul(&temp, &temp, &D);
    bn_sub(&D, &A, &D);
    bn_sub(&D, &C, &D);
    bn_add(&D, &D, &D);
    // bn_mod(&D, p, &D); // fix with mod_tmp
    init_zero(&mod_tmp);
    bn_mod(&mod_tmp, &D, p);
    bn_copy(&D, &mod_tmp);

    // X3 = D^2 - 2*A
    bn_mul(&D, &D, &R->X);
    bn_sub(&R->X, &A, &R->X);
    bn_sub(&R->X, &A, &R->X);
    // bn_mod(&R->X, p, &R->X); // fix with mod_tmp
    init_zero(&mod_tmp);
    bn_mod(&mod_tmp, &R->X, p);
    bn_copy(&R->X, &mod_tmp);

    // Y3 = D*(A - X3) - 8*C
    bn_sub(&A, &R->X, &R->Y);
    bn_mul(&D, &R->Y, &R->Y);
    bn_mul(&C, &C, &temp);
    for (int i = 0; i < 3; i++) {
        bn_add(&temp, &temp, &temp);
    }
    bn_sub(&R->Y, &temp, &R->Y);
    // bn_mod(&R->Y, p, &R->Y); // fix with mod_tmp
    init_zero(&mod_tmp);
    bn_mod(&mod_tmp, &R->Y, p);
    bn_copy(&R->Y, &mod_tmp);

    // Z3 = 2*Y1*Z1
    bn_mul(&P->Y, &P->Z, &R->Z);
    bn_add(&R->Z, &R->Z, &R->Z);
    // bn_mod(&R->Z, p, &R->Z); // fix with mod_tmp
    init_zero(&mod_tmp);
    bn_mod(&mod_tmp, &R->Z, p);
    bn_copy(&R->Z, &mod_tmp);

    // Print results
    bn_print("<< A", &A);
    bn_print("<< B", &B);
    bn_print("<< C", &C);
    bn_print("<< D", &D);
    bn_print("<< X3", &R->X);
    bn_print("<< Y3", &R->Y);
    bn_print("<< Z3", &R->Z);


    // Free temporary BIGNUMs
    free_bignum(&A);
    free_bignum(&B);
    free_bignum(&C);
    free_bignum(&D);
    free_bignum(&temp);
    free_bignum(&mod_tmp);
}

// Jacobian point addition: R = P + Q
__device__ void jacobian_point_add(JacobianPoint *R, JacobianPoint *P, JacobianPoint *Q, BIGNUM *p) {
    // Handle special cases
    if (is_point_at_infinity(P)) {
        *R = *Q;
        return;
    }
    if (is_point_at_infinity(Q)) {
        *R = *P;
        return;
    }

    BIGNUM U1, U2, S1, S2, H, r;
    init_zero(&U1);
    init_zero(&U2);
    init_zero(&S1);
    init_zero(&S2);
    init_zero(&H);
    init_zero(&r);

    // U1 = X1*Z2^2
    bn_mul(&P->X, &Q->Z, &U1);
    bn_mul(&U1, &Q->Z, &U1);
    bn_mod(&U1, &U1, p);

    // U2 = X2*Z1^2
    bn_mul(&Q->X, &P->Z, &U2);
    bn_mul(&U2, &P->Z, &U2);
    bn_mod(&U2, &U2, p);

    // S1 = Y1*Z2^3
    bn_mul(&P->Y, &Q->Z, &S1);
    bn_mul(&S1, &Q->Z, &S1);
    bn_mul(&S1, &Q->Z, &S1);
    bn_mod(&S1, &S1, p);

    // S2 = Y2*Z1^3
    bn_mul(&Q->Y, &P->Z, &S2);
    bn_mul(&S2, &P->Z, &S2);
    bn_mul(&S2, &P->Z, &S2);
    bn_mod(&S2, &S2, p);

    // Debug print
    bn_print("U1: ", &U1);
    bn_print("U2: ", &U2);
    bn_print("S1: ", &S1);
    bn_print("S2: ", &S2);

    // Check if P == Q, if so, use point doubling
    if (bn_cmp(&U1, &U2) == 0 && bn_cmp(&S1, &S2) == 0) {
        jacobian_point_double(R, P, p);
        return;
    }

    // H = U2 - U1
    bn_sub(&U2, &U1, &H);
    if (H.neg) {
        bn_add(&H, p, &H);
    }

    // r = S2 - S1
    bn_sub(&S2, &S1, &r);
    if (r.neg) {
        bn_add(&r, p, &r);
    }

    // Debug print
    bn_print("H: ", &H);
    bn_print("r: ", &r);

    BIGNUM H2, H3, U1H2;
    init_zero(&H2);
    init_zero(&H3);
    init_zero(&U1H2);

    // H2 = H^2
    bn_mul(&H, &H, &H2);
    bn_mod(&H2, p, &H2);

    // H3 = H*H2
    bn_mul(&H, &H2, &H3);
    bn_mod(&H3, p, &H3);

    // U1H2 = U1*H2
    bn_mul(&U1, &H2, &U1H2);
    bn_mod(&U1H2, p, &U1H2);

    // X3 = r^2 - H3 - 2*U1H2
    bn_mul(&r, &r, &R->X);
    bn_sub(&R->X, &H3, &R->X);
    bn_sub(&R->X, &U1H2, &R->X);
    bn_sub(&R->X, &U1H2, &R->X);
    bn_mod(&R->X, p, &R->X);

    // Y3 = r*(U1H2 - X3) - S1*H3
    bn_sub(&U1H2, &R->X, &R->Y);
    bn_mul(&r, &R->Y, &R->Y);
    BIGNUM temp;
    init_zero(&temp);
    bn_mul(&S1, &H3, &temp);
    bn_sub(&R->Y, &temp, &R->Y);
    bn_mod(&R->Y, p, &R->Y);

    // Z3 = H*Z1*Z2
    bn_mul(&H, &P->Z, &R->Z);
    bn_mul(&R->Z, &Q->Z, &R->Z);
    bn_mod(&R->Z, p, &R->Z);

    // Debug print
    bn_print("X3: ", &R->X);
    bn_print("Y3: ", &R->Y);
    bn_print("Z3: ", &R->Z);

    // Free temporary BIGNUMs
    free_bignum(&U1);
    free_bignum(&U2);
    free_bignum(&S1);
    free_bignum(&S2);
    free_bignum(&H);
    free_bignum(&r);
    free_bignum(&H2);
    free_bignum(&H3);
    free_bignum(&U1H2);
    free_bignum(&temp);
}

__device__ void affine_to_jacobian(JacobianPoint *jac, EC_POINT *aff) {
    bn_copy(&jac->X, &aff->x);
    bn_copy(&jac->Y, &aff->y);
    bn_set_word(&jac->Z, 1);  // Z coordinate is 1 for affine points
    
    // Debug print
    bn_print("Jacobian X: ", &jac->X);
    bn_print("Jacobian Y: ", &jac->Y);
    bn_print("Jacobian Z: ", &jac->Z);
}

__device__ void jacobian_to_affine(EC_POINT *aff, JacobianPoint *jac, BIGNUM *p) {
    if (is_point_at_infinity(jac)) {
        init_point_at_infinity(aff);
        return;
    }

    BIGNUM z_inv, z_inv_squared, z_inv_cubed;
    init_zero(&z_inv);
    init_zero(&z_inv_squared);
    init_zero(&z_inv_cubed);

    // Compute z_inv = 1/Z
    bn_mod_inverse(&z_inv, &jac->Z, p);

    // Compute z_inv_squared = z_inv^2
    bn_mul(&z_inv, &z_inv, &z_inv_squared);
    bn_mod(&z_inv_squared, p, &z_inv_squared);

    // Compute z_inv_cubed = z_inv_squared * z_inv
    bn_mul(&z_inv_squared, &z_inv, &z_inv_cubed);
    bn_mod(&z_inv_cubed, p, &z_inv_cubed);

    // Compute x = X * z_inv_squared
    bn_mul(&jac->X, &z_inv_squared, &aff->x);
    bn_mod(&aff->x, p, &aff->x);

    // Compute y = Y * z_inv_cubed
    bn_mul(&jac->Y, &z_inv_cubed, &aff->y);
    bn_mod(&aff->y, p, &aff->y);

    // Debug print
    bn_print("Affine x: ", &aff->x);
    bn_print("Affine y: ", &aff->y);

    free_bignum(&z_inv);
    free_bignum(&z_inv_squared);
    free_bignum(&z_inv_cubed);
}