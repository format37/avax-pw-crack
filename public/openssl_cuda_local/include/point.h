struct EC_POINT {
  BIGNUM x; 
  BIGNUM y;
};

// In the current structure, we might use a specific value (e.g., 0 or -1) 
// to represent the components of the point at infinity.
// A version that uses 0 to signify the point at infinity could be:
__device__ int point_is_at_infinity(EC_POINT *P) {    
    if (bn_is_zero(&P->x) || bn_is_zero(&P->y)) {
        return 1; // P is the point at infinity
    }
    return 0; // P is not the point at infinity
}

__device__ void point_double(EC_POINT *P, EC_POINT *R, BIGNUM *p) {
    // Temporary storage for the calculations
    BIGNUM s, xR, yR, m;
    debug_printf("point_double 0\n");
    if (point_is_at_infinity(P)) {
        debug_printf("point_double 1\n");
        // Point doubling at infinity remains at infinity
        set_bn(&R->x, &P->x);  // Copying P->x to R->x, assuming these are in the proper zeroed state
        set_bn(&R->y, &P->y);  // Copying P->y to R->y
        debug_printf("# 2\n");
        return;
    }
    debug_printf("point_double 3\n");

    // Calculate m = 3x^2 + a (a is zero for secp256k1)
    mod_mul(&P->x, &P->x, p, &m);  // m = x^2 mod p
    debug_printf("point_double 4\n");
    set_bn(&s, &m);                 // s = x^2 (Since we use a=0 in secp256k1, skip adding 'a')
    bn_add(&m, &m, &s);             // s = 2x^2
    bn_add(&s, &m, &s);             // s = 3x^2
    
    // Calculate s = (3x^2 + a) / (2y) = (s) / (2y)
    // First, compute the modular inverse of (2y)
    BIGNUM two_y;
    debug_printf("point_double 5\n");
    set_bn(&two_y, &P->y);         // Assuming set_bn simply duplicates P->y
    debug_printf("point_double 6\n");
    bn_add(&two_y, &two_y, &two_y); // two_y = 2y
    BIGNUM inv_two_y;
    debug_printf("point_double 7\n");
    mod_inv(&two_y, p, &inv_two_y);  // Compute the inverse of 2y
    debug_printf("point_double 8\n");

    mod_mul(&s, &inv_two_y, p, &s);  // Finally, s = (3x^2 + a) / (2y) mod p
    
    // Compute xR = s^2 - 2x mod p
    mod_mul(&s, &s, p, &xR);        // xR = s^2 mod p    
    set_bn(&m, &P->x);              // m = x
    
    bn_add(&m, &m, &m);             // m = 2x
    bn_subtract(&xR, &m, &xR);           // xR = s^2 - 2x
    bn_mod(&xR, p, &xR);            // Modulo operation

    // Compute yR = s * (x - xR) - y mod p
    bn_subtract(&P->x, &xR, &yR);        // yR = x - xR
    mod_mul(&s, &yR, p, &yR);       // yR = s * (x - xR)
    bn_subtract(&yR, &P->y, &yR);        // yR = s * (x - xR) - y
    bn_mod(&yR, p, &yR);            // Modulo operation

    // Copy results to R only after all calculations are complete to allow in-place doubling (P == R)
    set_bn(&R->x, &xR);
    set_bn(&R->y, &yR);
}

__device__ void copy_point(EC_POINT *dest, EC_POINT *src) {
    // Assuming EC_POINT contains BIGNUM structures for x and y,
    // and that BIGNUM is a structure that contains an array of BN_ULONG for the digits,
    // along with other metadata (like size, top, neg, etc.)

    // init the dest point
    init_zero(&dest->x);
    init_zero(&dest->y);

    // Copy the BIGNUM x
    bn_copy(&dest->x, &src->x);

    // Copy the BIGNUM y
    bn_copy(&dest->y, &src->y);
}

__device__ void set_point_at_infinity(EC_POINT *point) {
    // Assuming EC_POINT is a structure containing BIGNUM x and y
    // and that a BIGNUM value of NULL or {0} represents the point at infinity

    // To set the point at infinity, one straightforward way is to assign
    // a null pointer to x and y if the BIGNUM structure allows it, or 
    // set their values to some predetermined sentinel value that indicates
    // the point at infinity.

    // If using the sentinel value approach - ensure BIGNUM is set in a way
    // that other functions can check for it and treat it as infinity

    // To set the point to 0 (as an example sentinel value), do:
    init_zero(&point->x);
    init_zero(&point->y);// Ensure that this logic matches how you identify point at infinity elsewhere
}

__device__ int point_add(
    EC_POINT *result, 
    EC_POINT *p1, 
    EC_POINT *p2, 
    BIGNUM *p, 
    BIGNUM *a
) {
    bool debug = 0;
    if (debug) {
        printf("++ point_add ++\n");    
        bn_print(">> p1.x: ", &p1->x);
        bn_print(">> p1.y: ", &p1->y);
        bn_print(">> p2.x: ", &p2->x);
        bn_print(">> p2.y: ", &p2->y);
        bn_print(">> p: ", p);
        printf(">> p.top: %d\n", p->top);
        printf(">> p.neg: %d\n", p->neg);
        bn_print(">> a: ", a);
        printf(">> a.top: %d\n", a->top);
        printf(">> a.neg: %d\n", a->neg);
    }

    // Handle the point at infinity cases
    if (point_is_at_infinity(p1)) {
        copy_point(result, p2);
        if (debug) printf("p1 point at infinity\n");
        return 0;
    }

    if (point_is_at_infinity(p2)) {
        copy_point(result, p1);
        if (debug) printf("p2 point at infinity\n");
        return 0;
    }

    

    // Initialize temporary BIGNUMs for calculation
    BIGNUM s, x3, y3, tmp1, tmp2, tmp3, two, tmp1_squared;
    init_zero(&s);
    init_zero(&x3);
    init_zero(&y3);
    init_zero(&tmp1);
    init_zero(&tmp2);
    init_zero(&tmp3);
    init_zero(&two);
    init_zero(&tmp1_squared);

    // Case 1: p1 = p2 && p1.y != p2.y
    if (bn_cmp(&p1->x, &p2->x) == 0 && bn_cmp(&p1->y, &p2->y) != 0) {
        // The points are inverses to one another, return point at infinity
        if (debug) printf("The points are inverses to one another\n");
        set_point_at_infinity(result);
        return 0;
    }

    

    // Case 3: p1 == p2
    if (bn_cmp(&p1->x, &p2->x) == 0) {
        // Point doubling
        init_zero(&two);
        bn_set_word(&two, 2);

        // BIGNUM tmp1_squared;
        init_zero(&tmp1_squared);
        init_zero(&tmp1);
        bn_copy(&tmp1, &p1->x); // dst << src
        if (debug) {
            bn_print("\n[0] >> bn_mul p1.x: ", &p1->x);
            bn_print("[0] >> bn_mul tmp1: ", &tmp1);
        }
        bn_mul(&p1->x, &tmp1, &tmp1_squared);     // tmp1_squared = p1.x^2 // a * b = product
        if (debug) {
            bn_print("[0] << bn_mul tmp1: ", &tmp1_squared);
        }

        init_zero(&tmp1);
        bn_copy(&tmp1, &tmp1_squared); // dst << src
        // Init tmp2 as 3
        init_zero(&tmp2);
        bn_set_word(&tmp2, 3);
        bn_mul(&tmp1, &tmp2, &tmp1_squared);     // a * b = product
        if (debug) bn_print("\n[1] << bn_mul tmp1_squared: ", &tmp1_squared); // OK

        if (debug) bn_print("\n[2] << bn_add tmp1_squared: ", &tmp1_squared); // 

        init_zero(&tmp1);
        if (debug) bn_print("\n# [3] >> bn_mod tmp1_squared: ", &tmp1_squared);
        bn_copy(&tmp1, &tmp1_squared); // dst << src        
        if (debug) bn_print("# [3] >> bn_mod tmp1: ", &tmp1);
        init_zero(&tmp1_squared);
        if (debug) bn_print("[3] >> bn_mod tmp1_squared: ", &tmp1_squared);
        if (debug) bn_print("[3] >> bn_mod tmp1: ", &tmp1);
        if (debug) bn_print("[3] >> bn_mod p: ", p);
        bn_mod(&tmp1_squared, &tmp1, p);           // tmp1_squared = tmp1 mod p
        if (debug) bn_print("[3] << bn_mod tmp1_squared: ", &tmp1_squared); // OK
        if (debug) bn_print("[3] << bn_mod tmp1: ", &tmp1);
        
        init_zero(&tmp2);
        bn_set_word(&two, 2);
        bn_mul(&p1->y, &two, &tmp2);  // tmp2 = 2 * p1.y
        if (debug) bn_print("\n[4] << bn_mul tmp2: ", &tmp2); // OK

        init_zero(&tmp3);
        bn_copy(&tmp3, &tmp2); // dst << src
        bn_mod(&tmp2, &tmp3, p);           // tmp2 = tmp3 mod p
        if (debug) bn_print("\n[5] << bn_mod tmp2: ", &tmp2); // OK
        
        init_zero(&tmp3);
        bn_copy(&tmp3, &tmp2); // dst << src
        init_zero(&tmp2);
        if (debug) bn_print("\n[6] >> bn_mod_inverse tmp2: ", &tmp2);
        if (debug) bn_print("[6] >> bn_mod_inverse tmp3: ", &tmp3);
        if (debug) bn_print("[6] >> bn_mod_inverse p: ", p);
        bn_mod_inverse(&tmp2, &tmp3, p);  // tmp2 = tmp3 mod p
        if (debug) bn_print("[6] << bn_mod_inverse tmp2: ", &tmp2); // 
        init_zero(&tmp3);
        bn_copy(&tmp3, &tmp1_squared); // dst << src
        if (debug) bn_print("\n[7] >> bn_mul tmp3: ", &tmp3);
        if (debug) bn_print("[7] >> bn_mul tmp2: ", &tmp2);
        bn_mul(&tmp3, &tmp2, &s);  // tmp1 * tmp2 = s
        if (debug) bn_print("[7] << bn_mul s: ", &s); //

        init_zero(&tmp3);
        bn_copy(&tmp3, &s); // dst << src
        bn_mod(&s, &tmp3, p);  // s = s mod p
        if (debug) bn_print("\n[8] << bn_mod s: ", &s); //

        init_zero(&tmp3);
        bn_copy(&tmp3, &s); // dst << src
        bn_mul(&tmp3, &tmp3, &x3);  // x3 = s^2
        bn_subtract(&x3, &x3, &p1->x);  // x3 = x3 - p1.x
        bn_subtract(&x3, &x3, &p1->x);  // x3 = x3 - p1.x
        init_zero(&tmp3);
        bn_copy(&tmp3, &x3); // dst << src
        bn_mod(&x3, &tmp3, p);  // x3 = x3 mod p
        init_zero(&tmp1);
        bn_subtract(&tmp1, &p1->x, &x3);  // tmp1 = p1.x - x3
        init_zero(&tmp3);
        bn_copy(&tmp3, &s); // dst << src
        bn_mul(&tmp3, &tmp1, &y3);  // y3 = s * tmp1
        init_zero(&tmp3);
        bn_copy(&tmp3, &y3); // dst << src
        bn_subtract(&y3, &tmp3, &p1->y);  // y3 = y3 - p1.y
        init_zero(&tmp3);
        bn_copy(&tmp3, &y3); // dst << src
        bn_mod(&y3, &tmp3, p);  // y3 = y3 mod p
    } else {
        // Case 2: p1 != p2
        // Regular point addition
        bn_subtract(&tmp1, &p2->y, &p1->y);
        init_zero(&tmp3);
        bn_copy(&tmp3, &tmp1); // dst << src
        init_zero(&tmp1);
        bn_mod(&tmp1, &tmp3, p);           // tmp1 = (p2.y - p1.y) mod p 
        init_zero(&tmp2);
        bn_subtract(&tmp2, &p2->x, &p1->x);
        init_zero(&tmp3);
        bn_copy(&tmp3, &tmp2);
        bn_mod(&tmp2, &tmp3, p);           // tmp2 = (p2.x - p1.x) mod p
        init_zero(&tmp3);
        bn_copy(&tmp3, &tmp2);
        init_zero(&tmp2);
        bn_mod_inverse(&tmp2, &tmp3, p);
        init_zero(&s);
        bn_mul(&tmp1, &tmp2, &s);
        init_zero(&tmp2);
        bn_copy(&tmp2, &s);
        init_zero(&s);
        bn_mod(&s, &tmp2, p);                 // s = (p2.y - p1.y) / (p2.x - p1.x) mod p
        init_zero(&tmp2);
        bn_copy(&tmp2, &s);
        bn_mul(&s, &tmp2, &x3); // a * b = product // x3 = s^2
        init_zero(&tmp2);
        bn_copy(&tmp2, &x3);
        bn_subtract(&x3, &tmp2, &p1->x); // result = a - b
        bn_subtract(&x3, &x3, &p2->x);          // x3 = s^2 - p1.x - p2.x
        init_zero(&tmp2);
        bn_copy(&tmp2, &x3);
        bn_mod(&x3, &tmp2, p); // x3 = tmp2 mod p
        bn_subtract(&tmp1, &p1->x, &x3);
        bn_mul(&s, &tmp1, &y3); // a * b = product
        init_zero(&tmp2);
        bn_copy(&tmp2, &y3);
        bn_subtract(&y3, &tmp2, &p1->y);          // y3 = s * (p1.x - x3) - p1.y
        init_zero(&tmp2);
        bn_copy(&tmp2, &y3);
        bn_mod(&y3, &tmp2, p);               // y3 = tmp2 mod p
    }

    // Assign the computed coordinates to the result
    bn_copy(&result->x, &x3);
    bn_copy(&result->y, &y3);

    // Free the dynamically allocated memory
    free_bignum(&s);
    free_bignum(&x3);
    free_bignum(&y3);
    free_bignum(&tmp1);
    free_bignum(&tmp2);
    free_bignum(&tmp3);
    free_bignum(&two);
    free_bignum(&tmp1_squared);

    return 0;
}

__device__ void init_point_at_infinity(EC_POINT *P) {
    // For the x and y coordinates of P, we'll set the 'top' to 0,
    // which is our chosen convention for representing the point at infinity.

    init_zero(&P->x);
    init_zero(&P->y);

    P->x.top = 1; // No valid 'words' in the BIGNUM representing x
    P->y.top = 1; // No valid 'words' in the BIGNUM representing y
    
    // If 'd' arrays have been allocated, set them to zero as well.
    // memset could potentially be used for this if available and if 'd' is allocated.
    // Alternatively, if you use flags or other conventions for points at infinity,
    // set them accordingly here.
}

__device__ EC_POINT ec_point_scalar_mul(
    EC_POINT *point, 
    BIGNUM *scalar, 
    BIGNUM *curve_prime, 
    BIGNUM *curve_a
    ) {
    debug_printf("++ ec_point_scalar_mul ++\n");
    bn_print(">> point x: ", &point->x);
    bn_print(">> point y: ", &point->y);
    bn_print(">> scalar: ", scalar);
    bn_print(">> curve_prime: ", curve_prime);
    bn_print(">> curve_a: ", curve_a);
    
    EC_POINT current = *point; // This initializes the current point with the input point
    EC_POINT result; // Initialize the result variable, which accumulates the result
    EC_POINT tmp_result;
    EC_POINT tmp_a;
    EC_POINT tmp_b;                                     
    
    init_point_at_infinity(&result);                 // Initialize it to the point at infinity
    init_point_at_infinity(&tmp_result);                 // Initialize it to the point at infinity
    init_point_at_infinity(&tmp_a);                 // Initialize it to the point at infinity
    init_point_at_infinity(&tmp_b);                 // Initialize it to the point at infinity
    
    // Convert scalar BIGNUM to an array of integers that's easy to iterate bit-wise
    unsigned int bits[256];                          // Assuming a 256-bit scalar
    bignum_to_bit_array(scalar, bits);    
    for (int i = 0; i < 256; i++) {                 // Assuming 256-bit scalars        

        if (bits[i]) {// If the i-th bit is set
            init_point_at_infinity(&tmp_result);
            point_add(&tmp_result, &result, &current, curve_prime, curve_a);  // Add current to the result

            init_point_at_infinity(&result); // Reset result
            bn_copy(&result.x, &tmp_result.x);
            bn_copy(&result.y, &tmp_result.y);            
        }
        // init tmp_result
        init_point_at_infinity(&tmp_result);
        // init tmp_a
        init_point_at_infinity(&tmp_a);
        // init tmp_b
        init_point_at_infinity(&tmp_b);
        // Copy current to tmp_a
        bn_copy(&tmp_a.x, &current.x);
        bn_copy(&tmp_a.y, &current.y);
        // Copy current to tmp_b
        bn_copy(&tmp_b.x, &current.x);
        bn_copy(&tmp_b.y, &current.y);
        point_add(&tmp_result, &tmp_a, &tmp_b, curve_prime, curve_a);  // Double current by adding to itself
        // Copy tmp_result to current
        bn_copy(&current.x, &tmp_result.x);
        bn_copy(&current.y, &tmp_result.y);
    }    
    // Copy current to result
    bn_print("3 result.x: ", &result.x);
    bn_print("3 result.y: ", &result.y);
    return result;
}