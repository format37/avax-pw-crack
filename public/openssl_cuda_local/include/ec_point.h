struct EC_POINT {
    BIGNUM x; 
    BIGNUM y;
    BIGNUM z;
};

// In the current structure, we might use a specific value (e.g., 0 or -1) 
// to represent the components of the point at infinity.
// A version that uses 0 to signify the point at infinity could be:
__device__ int point_is_at_infinity(EC_POINT *P) {
    /*debug_printf("# point_is_at_infinity:\n");
    bn_print("P->x: ", &P->x);
    bn_print("P->y: ", &P->y);
    debug_printf("# P->x.top: %d\n", P->x.top);*/
    /*if (P->x.top == 0) {
        debug_printf("returning 1\n");
        return 1; // P is the point at infinity
    }
    debug_printf("returning 0\n");
    return 0; // P is not the point at infinity*/
    
    
    //return P->x.top == 0; // Assuming a valid x coordinate can never have top == 0, except for the point at infinity
    if (bn_is_zero(&P->x) || bn_is_zero(&P->y)) {
        return 1; // P is the point at infinity
    }
    return 0; // P is not the point at infinity


    /*
    // Assuming the x-coordinate is represented as an array of BN_ULONG
    // with 'top' items, and that the point at infinity has all its
    // BN_ULONGs set to 0.
    
    // If we like to detect a "point at infinity" by checking if the first word
    // is zero and making an assumption that this can only happen for the point at infinity:
    if (P->x.top == 0 && P->x.d[0] == 0) {
        return 1; // P is the point at infinity
    }

    return 0; // P is not the point at infinity
    */
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
    // bn_sub(&xR, &m, &xR);           // xR = s^2 - 2x
    bn_subtract(&xR, &m, &xR);           // xR = s^2 - 2x
    bn_mod(&xR, p, &xR);            // Modulo operation

    // Compute yR = s * (x - xR) - y mod p
    // bn_sub(&P->x, &xR, &yR);        // yR = x - xR
    bn_subtract(&P->x, &xR, &yR);        // yR = x - xR
    mod_mul(&s, &yR, p, &yR);       // yR = s * (x - xR)
    // bn_sub(&yR, &P->y, &yR);        // yR = s * (x - xR) - y
    bn_subtract(&yR, &P->y, &yR);        // yR = s * (x - xR) - y
    bn_mod(&yR, p, &yR);            // Modulo operation

    // Copy results to R only after all calculations are complete to allow in-place doubling (P == R)
    set_bn(&R->x, &xR);
    set_bn(&R->y, &yR);
}

__device__ void copy_point(EC_POINT *dest, EC_POINT *src) {
    //printf("copy_point 0\n");
    // Assuming EC_POINT contains BIGNUM structures for x and y,
    // and that BIGNUM is a structure that contains an array of BN_ULONG for the digits,
    // along with other metadata (like size, top, neg, etc.)

    // init the dest point
    // dest->x.d = new BN_ULONG[MAX_BIGNUM_WORDS];
    // dest->y.d = new BN_ULONG[MAX_BIGNUM_WORDS];
    // dest->x.top = 0;
    // dest->y.top = 0;
    // dest->x.neg = 0;
    // dest->y.neg = 0;
    // dest->x.dmax = MAX_BIGNUM_WORDS;
    // dest->y.dmax = MAX_BIGNUM_WORDS;
    init_zero(&dest->x);
    init_zero(&dest->y);

    // Copy the BIGNUM x
    bn_copy(&dest->x, &src->x);
    /*for (int i = 0; i < src->x.top; i++) {
        printf("copy_point 1.%d\n", i);
        dest->x.d[i] = src->x.d[i];
    }    
    dest->x.neg = src->x.neg;
    dest->x.top = src->x.top;*/

    // Copy the BIGNUM y
    bn_copy(&dest->y, &src->y);
    /*
    for (int i = 0; i < src->y.top; i++) {
        dest->y.d[i] = src->y.d[i];
    }
    dest->y.neg = src->y.neg;
    dest->y.top = src->y.top;*/
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
    // bn_zero(&point->x); // A function that sets a BIGNUM to 0
    init_zero(&point->x);

    //bn_zero(&point->y); // Ensure that this logic matches how you identify point at infinity elsewhere
    init_zero(&point->y);
}

__device__ int point_add(
    EC_POINT *result, 
    EC_POINT *p1, 
    EC_POINT *p2, 
    BIGNUM *p, 
    BIGNUM *a
) {
    bool debug = 1;
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
        // if (debug) 
        if (debug) printf("p1 point at infinity\n");
        return 0;
    }

    // bn_print("\n### p1.x: ", &p1->x);
    // return 0;

    if (point_is_at_infinity(p2)) {
        copy_point(result, p1);
        // if (debug) 
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
        // if (debug) 
        if (debug) printf("The points are inverses to one another\n");
        set_point_at_infinity(result);
        return 0;
    }

    

    // Case 3: p1 == p2
    // TODO: Check, do we need to compare y
    //if (bn_cmp(&p1->x, &p2->x) == 0 && bn_cmp(&p1->y, &p2->y) == 0) {
    if (bn_cmp(&p1->x, &p2->x) == 0) {
        //if (debug) 
        debug_printf("p1.x == p2.x\n");
        // Point doubling
        // BIGNUM two;
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
            bn_print("[0] << bn_mul tmp1: ", &tmp1_squared); // ERR
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
        if (debug) bn_print("[6] << bn_mod_inverse tmp2: ", &tmp2); // STUCK
        // return 0;//TODO: remove
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
        // bn_print("\n[9] << bn_mul x3: ", &x3); //

        bn_subtract(&x3, &x3, &p1->x);  // x3 = x3 - p1.x
        // bn_print("\n[10] << bn_subtract x3: ", &x3); //

        bn_subtract(&x3, &x3, &p1->x);  // x3 = x3 - p1.x
        // bn_print("\n[11] << bn_subtract x3: ", &x3); //

        init_zero(&tmp3);
        bn_copy(&tmp3, &x3); // dst << src
        bn_mod(&x3, &tmp3, p);  // x3 = x3 mod p
        // bn_print("\n[12] << bn_mod x3: ", &x3); // OK

        init_zero(&tmp1);
        // bn_print("[13] >> bn_subtract p1.x: ", &p1->x); //
        // bn_print("[13] >> bn_subtract x3: ", &x3); //
        bn_subtract(&tmp1, &p1->x, &x3);  // tmp1 = p1.x - x3
        // bn_print("\n[13] << bn_subtract tmp1: ", &tmp1); //

        init_zero(&tmp3);
        bn_copy(&tmp3, &s); // dst << src
        bn_mul(&tmp3, &tmp1, &y3);  // y3 = s * tmp1
        // bn_print("\n[14] << bn_mul y3: ", &y3); //

        //init_zero(&y3, MAX_BIGNUM_SIZE);
        init_zero(&tmp3);
        bn_copy(&tmp3, &y3); // dst << src
        // bn_print("[15] >> bn_subtract tmp3: ", &tmp3); //
        // bn_print("[15] >> bn_subtract p1.y: ", &p1->y); //
        bn_subtract(&y3, &tmp3, &p1->y);  // y3 = y3 - p1.y
        // bn_print("\n[15] << bn_subtract y3: ", &y3); //

        init_zero(&tmp3);
        bn_copy(&tmp3, &y3); // dst << src
        bn_mod(&y3, &tmp3, p);  // y3 = y3 mod p
        // bn_print("\n[16] << bn_mod y3: ", &y3); //
    } else {
        // Case 2: p1 != p2
        //if (debug) 
        debug_printf("p1.x != p2.x\n");
        // Regular point addition
        bn_subtract(&tmp1, &p2->y, &p1->y);
        // bn_print("\n[a] << bn_subtract tmp1: ", &tmp1);
        init_zero(&tmp3);
        bn_copy(&tmp3, &tmp1); // dst << src
        // bn_mod(&tmp1, p, &tmp1);           // tmp1 = (p2.y - p1.y) mod p
        init_zero(&tmp1);
        // bn_print("\n[c] >> bn_mod tmp3: ", &tmp3);
        // bn_print("\n[c] >> bn_mod p: ", p);        
        bn_mod(&tmp1, &tmp3, p);           // tmp1 = (p2.y - p1.y) mod p 
        // bn_print("\n[c] << bn_mod tmp1: ", &tmp1); // OK
        
        init_zero(&tmp2);
        bn_subtract(&tmp2, &p2->x, &p1->x);

        init_zero(&tmp3);
        bn_copy(&tmp3, &tmp2);
        //bn_mod(&tmp2, p, &tmp2);           // tmp2 = (p2.x - p1.x) mod p
        // bn_print("\n[d] >> bn_mod tmp3: ", &tmp3);
        // bn_print("\n[d] >> bn_mod p: ", p);
        bn_mod(&tmp2, &tmp3, p);           // tmp2 = (p2.x - p1.x) mod p
        // bn_print("\n[d] << bn_mod tmp2: ", &tmp2);

        // bn_print("\n[0] >> bn_mod_inverse tmp2: ", &tmp2);
        // bn_print("[0] >> bn_mod_inverse tmp3: ", &tmp3);
        // bn_print("[0] >> bn_mod_inverse p: ", p);
        init_zero(&tmp3);
        bn_copy(&tmp3, &tmp2);
        init_zero(&tmp2);
        //bn_mod_inverse(&tmp2, p, &tmp3);   // tmp2 = (p2.x - p1.x)^-1 mod p
        bn_mod_inverse(&tmp2, &tmp3, p);
        // bn_print("\n[1] << bn_mod_inverse tmp2: ", &tmp2); // OK
        // mul(a, b, product)
        //bn_mul(&s, &tmp1, &tmp2);          // s = (p2.y - p1.y) * (p2.x - p1.x)^-1
        // bn_print("\n[2] >> bn_mul s: ", &s);
        // bn_print("\n[2] >> bn_mul tmp1: ", &tmp1);
        // bn_print("\n[2] >> bn_mul tmp2: ", &tmp2);
        init_zero(&s);
        bn_mul(&tmp1, &tmp2, &s);
        // bn_print("\n[2] << bn_mul s: ", &s);
        // bn_print("\n[2] << bn_mul tmp1: ", &tmp1);
        // bn_print("\n[2] << bn_mul tmp2: ", &tmp2); // OK

        
        init_zero(&tmp2);
        // bn_print("\n[3a] >> bn_mod s: ", &s);
        bn_copy(&tmp2, &s);
        init_zero(&s);
        // bn_print("\n[3b] >> bn_mod s: ", &s);
        // bn_print("\n[3] >> bn_mod tmp2: ", &tmp2);
        // bn_print("\n[3] >> bn_mod p: ", p); // OK
        bn_mod(&s, &tmp2, p);                 // s = (p2.y - p1.y) / (p2.x - p1.x) mod p
        // bn_print("\n[3] << bn_mod s: ", &s); // OK

        init_zero(&tmp2);
        bn_copy(&tmp2, &s);
        // bn_print("\n[4] >> bn_mul x3: ", &x3);
        // bn_print("\n[4] >> bn_mul s: ", &s);
        // bn_print("\n[4] >> bn_mul tmp2: ", &tmp2);
        bn_mul(&s, &tmp2, &x3); // a * b = product // x3 = s^2
        // bn_print("\n[4] << bn_mul x3: ", &x3); // 
        // bn_print("\n[4] << bn_mul s: ", &s);

        //bn_mod(&x3, p, &x3);               // x3 = s^2 mod p
        init_zero(&tmp2);
        bn_copy(&tmp2, &x3);
        // bn_print("\n[5] >> bn_subtract x3: ", &x3);
        // bn_print("\n[5] >> bn_subtract tmp2: ", &tmp2);
        // print p1.x
        // bn_print("\n[5] >> bn_subtract p1.x: ", &p1->x);
        bn_subtract(&x3, &tmp2, &p1->x); // result = a - b
        // bn_print("\n[5] << bn_subtract x3: ", &x3); //
        bn_subtract(&x3, &x3, &p2->x);          // x3 = s^2 - p1.x - p2.x
        // bn_print("\n[6] << bn_subtract x3: ", &x3);
        
        init_zero(&tmp2);
        //bn_mod(&x3, p, &x3); // x3 = (s^2 - p1.x - p2.x) mod p tmp2 = 
        bn_copy(&tmp2, &x3);
        // bn_print("\n[7] >> bn_mod x3: ", &x3);
        // bn_print("\n[7] >> bn_mod tmp2: ", &tmp2);
        // bn_print("\n[7] >> bn_mod p: ", p);
        bn_mod(&x3, &tmp2, p); // x3 = tmp2 mod p
        // bn_print("\n[7] << bn_mod x3: ", &x3); // OK

        bn_subtract(&tmp1, &p1->x, &x3);
        // bn_print("\n[8] << bn_subtract tmp1: ", &tmp1); // OK

        //bn_mul(&y3, &s, &tmp1);            // y3 = s * (p1.x - x3)
        bn_mul(&s, &tmp1, &y3); // a * b = product
        // bn_print("\n[9] << bn_mul y3: ", &y3); // OK

        //bn_mod(&y3, p, &y3);               // y3 = s * (p1.x - x3) mod p
        
        init_zero(&tmp2);
        bn_copy(&tmp2, &y3);
        bn_subtract(&y3, &tmp2, &p1->y);          // y3 = s * (p1.x - x3) - p1.y
        // bn_print("\n[10] << bn_mod y3: ", &y3); // OK

        init_zero(&tmp2);
        bn_copy(&tmp2, &y3);
        bn_mod(&y3, &tmp2, p);               // y3 = tmp2 mod p
        // bn_print("\n[11] << bn_mod y3: ", &y3);
    }

    // Assign the computed coordinates to the result
    // copy_bn(&result->x, &x3);
    // copy_bn(&result->y, &y3);
    bn_copy(&result->x, &x3);
    bn_copy(&result->y, &y3);

    // print
    bn_print("\n<< result->x: ", &result->x);
    bn_print("<< result->y: ", &result->y);

    // Free the dynamically allocated memory
    free_bignum(&s);
    free_bignum(&x3);
    free_bignum(&y3);
    free_bignum(&tmp1);
    free_bignum(&tmp2);
    free_bignum(&tmp3);
    free_bignum(&two);
    free_bignum(&tmp1_squared);
    printf("-- point_add --\n");
    return 0;
}

__device__ void init_point_at_infinity(EC_POINT *P) {
    // printf("++ init_point_at_infinity ++\n");
    // For the x and y coordinates of P, we'll set the 'top' to 0,
    // which is our chosen convention for representing the point at infinity.

    init_zero(&P->x);
    init_zero(&P->y);

    P->x.top = 1; // No valid 'words' in the BIGNUM representing x
    P->y.top = 1; // No valid 'words' in the BIGNUM representing y
    
    // If 'd' arrays have been allocated, set them to zero as well.
    // memset could potentially be used for this if available and if 'd' is allocated.
    
    // for (int i = 0; i < P->x.dmax; ++i) {
    //     P->x.d[i] = 0;
    // }
    
    // for (int i = 0; i < P->y.dmax; ++i) {
    //     P->y.d[i] = 0;
    // }
    // printf("### mark\n");
    // Alternatively, if you use flags or other conventions for points at infinity,
    // set them accordingly here.
    // printf("-- init_point_at_infinity --\n");
}

__device__ EC_POINT ec_point_scalar_mul(
    EC_POINT *point, 
    BIGNUM *scalar, 
    BIGNUM *curve_prime, 
    BIGNUM *curve_a
    ) {
    debug_printf("++ ec_point_scalar_mul ++\n");

    unsigned int debug_addictions_count = 0;
    // Print point
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
    scalar->top = find_top(scalar);
    bignum_to_bit_array(scalar, bits);
    
    // printf("coef hex: %s\n", bignum_to_hex(scalar)); // Convert BIGNUM to hex string for printing
    bn_print("coef: ", scalar);  
    
    for (int i = 0; i < 256; i++) {                 // Assuming 256-bit scalars // TODO: ENABLE THIS
    //for (int i = 0; i < 3; i++) {                 // DEBUG
        // printf("\n### Step: %d\n", i);
        // if (i<debug_counter) {
        //     // printf("0 x: %s\n", bignum_to_hex(&current.x));
        //     bn_print("0 current.x: ", &current.x);
        //     // printf("0 y: %s\n", bignum_to_hex(&current.y));
        //     bn_print("0 current.y: ", &current.y);
        // }
        

        if (bits[i]) {// If the i-th bit is set
        // if (true) {// DEBUG
            // printf("\n[0]\n");
            // printf("0: Interrupting for debug\n");
            // return result; // TODO: remove this
            // if (i<debug_counter) printf("# 0\n");
            // init tmp_result
            init_point_at_infinity(&tmp_result); 
            
            bn_print(">> point_add result.x: ", &result.x);
            bn_print(">> point_add result.y: ", &result.y);
            bn_print(">> point_add current.x: ", &current.x);
            bn_print(">> point_add current.y: ", &current.y);
            bn_print(">> curve_prime: ", curve_prime);
            bn_print(">> curve_a: ", curve_a);
            
            // bn_print(">> INITIAL result.x: ", &result.x);
            // bn_print(">> INITIAL result.y: ", &result.y);            

            point_add(&tmp_result, &result, &current, curve_prime, curve_a);  // Add current to the result
            debug_addictions_count++;

            init_point_at_infinity(&result); // Reset result
            bn_copy(&result.x, &tmp_result.x);
            bn_copy(&result.y, &tmp_result.y);
            bn_print("<< point_add result.x: ", &result.x);
            bn_print("<< point_add result.y: ", &result.y);

            // return result; // TODO: remove this
            
            // if (i<debug_counter) printf("# b\n");
            // printf("1 x: %s\n", bignum_to_hex(&result.x));
            //  if (i<debug_counter) bn_print("1 result.x: ", &result.x);
            // printf("1 y: %s\n", bignum_to_hex(&result.y));
            //  if (i<debug_counter) bn_print("1 result.y: ", &result.y);
            // printf("\n");
            
        }
        // printf("\n[1]\n");
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

        // printf("\n[1]\n");
        bn_print(">> point_add tmp_a.x: ", &tmp_a.x);
        bn_print(">> point_add tmp_a.y: ", &tmp_a.y);
        bn_print(">> point_add tmp_b.x: ", &tmp_b.x);
        bn_print(">> point_add tmp_b.y: ", &tmp_b.y);
        bn_print(">> point_add tmp_result.x: ", &tmp_result.x);
        bn_print(">> point_add tmp_result.y: ", &tmp_result.y);
        // print curve_prime and curve_a
        bn_print(">> point_add curve_prime: ", curve_prime);
        bn_print(">> point_add curve_a: ", curve_a);

        point_add(&tmp_result, &tmp_a, &tmp_b, curve_prime, curve_a);  // Double current by adding to itself
        debug_addictions_count++;

        bn_print("\n<< point_add tmp_result.x (pp.x): ", &tmp_result.x);
        bn_print("<< point_add tmp_result.y (pp.y): ", &tmp_result.y);
        bn_print("<< point_add tmp_a.x (p1.x): ", &tmp_a.x);
        bn_print("<< point_add tmp_a.y (p1.y): ", &tmp_a.y);
        bn_print("<< point_add tmp_b.x (p2.x): ", &tmp_b.x);
        bn_print("<< point_add tmp_b.y (p2.y):", &tmp_b.y);
        bn_print("<< point_add curve_prime: ", curve_prime);
        bn_print("<< point_add curve_a: ", curve_a);

        // Copy tmp_result to current
        bn_copy(&current.x, &tmp_result.x);
        bn_copy(&current.y, &tmp_result.y);
        bn_print("\n<< point_add current.x: ", &current.x);
        bn_print("<< point_add current.y: ", &current.y);

        // printf("2 x: %s\n", bignum_to_hex(&current.x));
        // if (i<debug_counter) bn_print("2 current.x: ", &current.x);
        // printf("2 y: %s\n", bignum_to_hex(&current.y));
        // print 2 result.x
        bn_print("2 result.x: ", &result.x);
        bn_print("2 result.y: ", &result.y);
        // break; // TODO: remove this
    }

    // // printf("Final x: %s\n", bignum_to_hex(&result.x));
    // bn_print("Final x: ", &result.x);
    // // printf("Final y: %s\n", bignum_to_hex(&result.y));
    // bn_print("Final y: ", &result.y);
    
    // Copy current to result
    // bn_copy(&result.x, &current.x);
    // bn_print("3 result.x: ", &result.x);
    // bn_print("3 result.y: ", &result.y);
    printf("debug_addictions_count: %d\n", debug_addictions_count);
    printf("-- ec_point_scalar_mul --\n");
    return result;
}

__device__ void GetPublicKey(uint8_t* buffer, uint8_t* key, uint8_t prefix)
{
    // uint8_t buffer[100];
    BIGNUM newKey;
    init_zero(&newKey);
    for (int i = 0; i < 4; ++i) {
        newKey.d[3 - i] = ((BN_ULONG)key[8*i] << 56) | 
                            ((BN_ULONG)key[8*i + 1] << 48) | 
                            ((BN_ULONG)key[8*i + 2] << 40) | 
                            ((BN_ULONG)key[8*i + 3] << 32) |
                            ((BN_ULONG)key[8*i + 4] << 24) | 
                            ((BN_ULONG)key[8*i + 5] << 16) | 
                            ((BN_ULONG)key[8*i + 6] << 8) | 
                            ((BN_ULONG)key[8*i + 7]);
    }
    printf("      * Cuda newKey:");
    bn_print("", &newKey);
    
    // Initialize constants //TODO: Move it outside of each THREAD. Call once before instead and then sync
    init_zero(&CURVE_A);
    
    // For secp256k1, CURVE_B should be initialized to 7 rather than 0
    init_zero(&CURVE_B);
    CURVE_B.d[0] = 0x7;

    BN_ULONG CURVE_GX_values[MAX_BIGNUM_SIZE] = {
        0x79BE667EF9DCBBAC,
        0x55A06295CE870B07,
        0x029BFCDB2DCE28D9,
        0x59F2815B16F81798
        };
    for (int j = 0; j < MAX_BIGNUM_SIZE; ++j) {
            CURVE_GX_d[j] = CURVE_GX_values[j];
        }

    // Generator y coordinate
    // BIGNUM CURVE_GY;
    BN_ULONG CURVE_GY_values[MAX_BIGNUM_SIZE] = {
        0x483ADA7726A3C465,
        0x5DA4FBFC0E1108A8,
        0xFD17B448A6855419,
        0x9C47D08FFB10D4B8
        };
    for (int j = 0; j < MAX_BIGNUM_SIZE; ++j) {
            CURVE_GY_d[j] = CURVE_GY_values[j];
        }

    // Initialize generator
    EC_POINT G;
    init_zero(&G.x);
    init_zero(&G.y);
    for (int j = 0; j < MAX_BIGNUM_SIZE; ++j) {
            G.x.d[j] = CURVE_GX_values[j];
            G.y.d[j] = CURVE_GY_values[j];
        }
    # define TEST_BIGNUM_WORDS 4
    // reverse
    reverse_order(&G.x, TEST_BIGNUM_WORDS);
    reverse_order(&G.y, TEST_BIGNUM_WORDS);
    // find top
    G.x.top = find_top(&G.x);
    G.y.top = find_top(&G.y);

    init_zero(&CURVE_P);
    // Init curve prime
    // fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
    BN_ULONG CURVE_P_values[MAX_BIGNUM_SIZE] = {
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFEFFFFFC2F,
        0,0,0,0        
        };
    for (int j = 0; j < MAX_BIGNUM_SIZE; ++j) {
            CURVE_P.d[j] = CURVE_P_values[j];
        }
    // reverse
    reverse_order(&CURVE_P, TEST_BIGNUM_WORDS);
    // find top
    CURVE_P.top = find_top(&CURVE_P);
    // TODO: Check do we need to define curves, G and do reversing
    EC_POINT publicKey = ec_point_scalar_mul(&G, &newKey, &CURVE_P, &CURVE_A);
    // print &publicKey.x
    printf("      * Cuda publicKey.x: ");
    bn_print("", &publicKey.x);
    // print &publicKey.y
    printf("      * Cuda publicKey.y: ");
    bn_print("", &publicKey.y);
    
    // Copy the public key to buffer
    // my_cuda_memcpy_uint32_t_to_unsigned_char(buffer, publicKey.x.d, 32);
    for (int i = 0; i < 4; i++) {
        buffer[8*i] = (publicKey.x.d[3 - i] >> 56) & 0xFF;
        buffer[8*i + 1] = (publicKey.x.d[3 - i] >> 48) & 0xFF;
        buffer[8*i + 2] = (publicKey.x.d[3 - i] >> 40) & 0xFF;
        buffer[8*i + 3] = (publicKey.x.d[3 - i] >> 32) & 0xFF;
        buffer[8*i + 4] = (publicKey.x.d[3 - i] >> 24) & 0xFF;
        buffer[8*i + 5] = (publicKey.x.d[3 - i] >> 16) & 0xFF;
        buffer[8*i + 6] = (publicKey.x.d[3 - i] >> 8) & 0xFF;
        buffer[8*i + 7] = publicKey.x.d[3 - i] & 0xFF;
    }

    printf("      * [0] Cuda Buffer after public key copy: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", buffer[i]);
    }
    printf("\n");

    // Shift the buffer by 1 byte
    for (int i = 33; i > 0; i--) {
        buffer[i] = buffer[i - 1];
    }
    // Add prefix before the buffer
    buffer[0] = prefix;
    // Print buffer value after adding prefix
    printf("      * [1] Cuda Buffer after adding prefix:");
    for (int i = 0; i < 33; i++) {
        printf("%02x", buffer[i]);
    }
    printf("\n");
    // return buffer;
}