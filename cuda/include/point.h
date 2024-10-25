#include "jacobian_point.h"

__device__ bool bn_mod_inverse(BIGNUM_CUDA *result, const BIGNUM_CUDA *a, const BIGNUM_CUDA *n) {
    #ifdef debug_print
        printf("++ bn_mod_inverse ++\n");
        bn_print(">> a: ", a);
        bn_print(">> n: ", n);
    #endif
    
    if (bn_is_one(n)) {
        return false;  // No modular inverse exists if modulus is 1
    }

    if (bn_is_one(a)) {
        // The modular inverse of 1 is 1
        init_one(result);
        return true;
    }

    BIGNUM_CUDA r;
    BIGNUM_CUDA nr;
    BIGNUM_CUDA t;
    BIGNUM_CUDA nt;
    BIGNUM_CUDA q;
    BIGNUM_CUDA tmp;
    BIGNUM_CUDA tmp2;
    BIGNUM_CUDA tmp3;

    init_zero(&r);
    init_zero(&nr);
    init_zero(&t);
    init_one(&nt);
    init_zero(&q);
    init_zero(&tmp);
    init_zero(&tmp2);
    init_zero(&tmp3);
    #ifdef debug_bn_copy
        printf("bn_mod_inverse: bn_copy(r, n)\n");
    #endif
    bn_copy(&r, n);
    bn_mod(&nr, a, n); // Compute non-negative remainder of 'a' modulo 'n'
    #ifdef debug_print
        unsigned int counter = 0;
    #endif
    while (!bn_is_zero(&nr)) {
        bn_div(&q, &tmp, &r, &nr); // Compute quotient and remainder
        #ifdef debug_bn_copy
            printf("bn_mod_inverse: bn_copy(tmp, nt)\n");
        #endif
        bn_copy(&tmp, &nt);
        bn_mul(&q, &nt, &tmp2); // tmp2 = q * nt
        init_zero(&tmp3);
        bn_sub(&tmp3, &t, &tmp2); // tmp3 = t - tmp2
        // if (tmp3.top!=find_top(&tmp3)) printf("*** hypotesis true: bn_sub top is not correct\n");
        #ifdef debug_bn_copy
            printf("bn_mod_inverse: bn_copy(nt, tmp3)\n");
        #endif
        bn_copy(&nt, &tmp3); // dst << src
        #ifdef debug_bn_copy
            printf("bn_mod_inverse: bn_copy(t, tmp)\n");
        #endif
        bn_copy(&t, &tmp);
        #ifdef debug_bn_copy
            printf("bn_mod_inverse: bn_copy(tmp, nr)\n");
        #endif
        bn_copy(&tmp, &nr);
        bn_mul(&q, &nr, &tmp2);
        init_zero(&tmp3);
        bn_sub(&tmp3, &r, &tmp2); // tmp3 = r - tmp2
        #ifdef debug_bn_copy
            printf("bn_mod_inverse: bn_copy(r, tmp3)\n");
        #endif
        bn_copy(&nr, &tmp3);
        #ifdef debug_bn_copy
            printf("bn_mod_inverse: bn_copy(r, tmp)\n");
        #endif
        bn_copy(&r, &tmp);        
        #ifdef debug_print
            counter++;
            printf("[%d] ", counter);
            bn_print(" t: ", &t);
        #endif
    }

    if (!bn_is_one(&r)) {
        init_zero(result);
        return false; // No modular inverse exists
    }

    if (t.neg != 0) {
        bn_add(&tmp2, &t, n); // tmp2 = t + n
        #ifdef debug_bn_copy
            printf("bn_mod_inverse: bn_copy(t, tmp2)\n");
        #endif
        bn_copy(&t, &tmp2);
    }
    #ifdef debug_bn_copy
        printf("bn_mod_inverse: bn_copy(result, t)\n");
    #endif
    bn_copy(result, &t);
    #ifdef debug_print
        bn_print("<< result: ", result);
        printf("-- bn_mod_inverse --\n");
    #endif
    return true;
}

// limit to 256 bits
__device__ void bignum_to_bit_array(BIGNUM_CUDA *n, unsigned int *bits) {
    #ifdef debug_print
        printf("++ bignum_to_bit_array ++\n");
        bn_print(">> n: ", n);
    #endif
    int index = 0;
    int total_bits = n->top * BN_ULONG_NUM_BITS;

    if (total_bits > MAX_BIT_ARRAY_SIZE) {
        total_bits = MAX_BIT_ARRAY_SIZE;
    }

    // Iterate through the words
    for (int i = 0; i < n->top && index < total_bits; ++i) {
        BN_ULONG word = n->d[i];
        for (int j = 0; j < BN_ULONG_NUM_BITS && index < total_bits; ++j) {
            bits[index++] = (word >> j) & 1;
        }
    }

    // Fill the remaining bits with zeros
    while (index < MAX_BIT_ARRAY_SIZE) {
        bits[index++] = 0;
    }
    #ifdef debug_print
        printf("<< bits (uint): ");
        for (int i = 0; i < MAX_BIT_ARRAY_SIZE; i++) {
            printf("%d", bits[i]);
        }
        printf("\n<< bits (hex): ");
        for (int i = 0; i < MAX_BIT_ARRAY_SIZE; i++) {
            printf("%x", bits[i]);
        }
        printf("-- bignum_to_bit_array --\n");
    #endif
}

// In the current structure, we might use a specific value (e.g., 0 or -1) 
// to represent the components of the point at infinity.
// A version that uses 0 to signify the point at infinity could be:
__device__ int point_is_at_infinity(const EC_POINT_CUDA *P) {    
    if (bn_is_zero(&P->x) || bn_is_zero(&P->y)) {
        return 1; // P is the point at infinity
    }
    return 0; // P is not the point at infinity
}

__device__ void copy_point(EC_POINT_CUDA *dest, EC_POINT_CUDA *src) {
    // Assuming EC_POINT_CUDA contains BIGNUM_CUDA structures for x and y,
    // and that BIGNUM_CUDA is a structure that contains an array of BN_ULONG for the digits,
    // along with other metadata (like size, top, neg, etc.)

    // init the dest point
    init_zero(&dest->x);
    init_zero(&dest->y);

    // Copy the BIGNUM_CUDA x
    #ifdef debug_bn_copy
        printf("copy_point: bn_copy(dest->x, src->x)\n");
    #endif
    bn_copy(&dest->x, &src->x);

    // Copy the BIGNUM_CUDA y
    #ifdef debug_bn_copy
        printf("copy_point: bn_copy(dest->y, src->y)\n");
    #endif
    bn_copy(&dest->y, &src->y);
}

__device__ int point_add_affine(
    EC_POINT_CUDA *result, 
    EC_POINT_CUDA *p1, 
    EC_POINT_CUDA *p2, 
    const BIGNUM_CUDA *p, 
    const BIGNUM_CUDA *a
) {
    bool debug = 0;
    if (debug) {
        printf("++ point_add ++\n");
        bn_print(">> p1.x: ", &p1->x);
        bn_print(">> p1.y: ", &p1->y);
        bn_print(">> p2.x: ", &p2->x);
        bn_print(">> p2.y: ", &p2->y);
        bn_print(">> p: ", p);
        bn_print(">> a: ", a);
    }
    // bn_print_no_fuse(">> p1.x: ", &p1->x);
    // bn_print_no_fuse(">> p1.y: ", &p1->y);
    // bn_print_no_fuse(">> p2.x: ", &p2->x);
    // bn_print_no_fuse(">> p2.y: ", &p2->y);
    // bn_print_no_fuse(">> p: ", p);
    // bn_print_no_fuse(">> a: ", a);
    debug = 0;
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
    BIGNUM_CUDA s, x3, y3, tmp1, tmp2, tmp3, two, tmp1_squared;
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

        // BIGNUM_CUDA tmp1_squared;
        init_zero(&tmp1_squared);
        init_zero(&tmp1);
        #ifdef debug_bn_copy
            printf("point_add: bn_copy(tmp1, p1->x)\n");
        #endif
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
        #ifdef debug_bn_copy
            printf("point_add: bn_copy(tmp1, tmp1_squared)\n");
        #endif
        bn_copy(&tmp1, &tmp1_squared); // dst << src
        // Init tmp2 as 3
        init_zero(&tmp2);
        bn_set_word(&tmp2, 3);
        bn_mul(&tmp1, &tmp2, &tmp1_squared);     // a * b = product
        if (debug) bn_print("\n[1] << bn_mul tmp1_squared: ", &tmp1_squared); // OK

        if (debug) bn_print("\n[2] << bn_add tmp1_squared: ", &tmp1_squared); // 

        init_zero(&tmp1);
        if (debug) bn_print("\n# [3] >> bn_mod tmp1_squared: ", &tmp1_squared);
        #ifdef debug_bn_copy
            printf("point_add: bn_copy(tmp1, tmp1_squared)\n");
        #endif
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
        #ifdef debug_bn_copy
            printf("point_add: bn_copy(tmp3, tmp2)\n");
        #endif
        bn_copy(&tmp3, &tmp2); // dst << src
        bn_mod(&tmp2, &tmp3, p);           // tmp2 = tmp3 mod p
        if (debug) bn_print("\n[5] << bn_mod tmp2: ", &tmp2); // OK
        
        init_zero(&tmp3);
        #ifdef debug_bn_copy
            printf("point_add: bn_copy(tmp3, tmp2)\n");
        #endif
        bn_copy(&tmp3, &tmp2); // dst << src
        init_zero(&tmp2);
        if (debug) bn_print("\n[6] >> bn_mod_inverse tmp2: ", &tmp2);
        if (debug) bn_print("[6] >> bn_mod_inverse tmp3: ", &tmp3);
        if (debug) bn_print("[6] >> bn_mod_inverse p: ", p);
        bn_mod_inverse(&tmp2, &tmp3, p);  // tmp2 = tmp3 mod p
        if (debug) bn_print("[6] << bn_mod_inverse tmp2: ", &tmp2); // 
        init_zero(&tmp3);
        #ifdef debug_bn_copy
            printf("point_add: bn_copy(tmp3, tmp1_squared)\n");
        #endif
        bn_copy(&tmp3, &tmp1_squared); // dst << src
        if (debug) bn_print("\n[7] >> bn_mul tmp3: ", &tmp3);
        if (debug) bn_print("[7] >> bn_mul tmp2: ", &tmp2);
        bn_mul(&tmp3, &tmp2, &s);  // tmp1 * tmp2 = s
        if (debug) bn_print("[7] << bn_mul s: ", &s); //

        init_zero(&tmp3);
        #ifdef debug_bn_copy
            printf("point_add: bn_copy(tmp3, s)\n");
        #endif
        bn_copy(&tmp3, &s); // dst << src
        bn_mod(&s, &tmp3, p);  // s = s mod p
        if (debug) bn_print("\n[8] << bn_mod s: ", &s); //

        init_zero(&tmp3);
        #ifdef debug_bn_copy
            printf("point_add: bn_copy(tmp3, s)\n");
        #endif
        bn_copy(&tmp3, &s); // dst << src
        bn_mul(&tmp3, &tmp3, &x3);  // x3 = s^2
        bn_sub(&x3, &x3, &p1->x);  // x3 = x3 - p1.x
        bn_sub(&x3, &x3, &p1->x);  // x3 = x3 - p1.x
        init_zero(&tmp3);
        #ifdef debug_bn_copy
            printf("point_add: bn_copy(tmp3, x3)\n");
        #endif
        bn_copy(&tmp3, &x3); // dst << src
        bn_mod(&x3, &tmp3, p);  // x3 = x3 mod p
        init_zero(&tmp1);
        bn_sub(&tmp1, &p1->x, &x3);  // tmp1 = p1.x - x3
        init_zero(&tmp3);
        #ifdef debug_bn_copy
            printf("point_add: bn_copy(tmp3, s)\n");
        #endif
        bn_copy(&tmp3, &s); // dst << src
        bn_mul(&tmp3, &tmp1, &y3);  // y3 = s * tmp1
        init_zero(&tmp3);
        #ifdef debug_bn_copy
            printf("point_add: bn_copy(tmp3, y3)\n");
        #endif
        bn_copy(&tmp3, &y3); // dst << src
        bn_sub(&y3, &tmp3, &p1->y);  // y3 = y3 - p1.y
        init_zero(&tmp3);
        #ifdef debug_bn_copy
            printf("point_add: bn_copy(tmp3, y3)\n");
        #endif
        bn_copy(&tmp3, &y3); // dst << src
        bn_mod(&y3, &tmp3, p);  // y3 = y3 mod p
    } else {
        // Case 2: p1 != p2
        if (debug) printf("p1 != p2\n");
        // Regular point addition
        bn_sub(&tmp1, &p2->y, &p1->y);
        if (debug) printf("# 0\n");
        init_zero(&tmp3);
        #ifdef debug_bn_copy
            printf("point_add: bn_copy(tmp3, tmp1)\n");
        #endif
        bn_copy(&tmp3, &tmp1); // dst << src
        if (debug) printf("# 1\n");
        init_zero(&tmp1);
        bn_mod(&tmp1, &tmp3, p);           // tmp1 = (p2.y - p1.y) mod p 
        if (debug) printf("# 2\n");
        init_zero(&tmp2);
        bn_sub(&tmp2, &p2->x, &p1->x);
        if (debug) printf("# 3\n");
        init_zero(&tmp3);
        #ifdef debug_bn_copy
            printf("point_add: bn_copy(tmp3, tmp2)\n");
        #endif
        bn_copy(&tmp3, &tmp2);
        if (debug) printf("# 4\n");
        bn_mod(&tmp2, &tmp3, p);           // tmp2 = (p2.x - p1.x) mod p
        if (debug) printf("# 5\n");
        init_zero(&tmp3);
        #ifdef debug_bn_copy
            printf("point_add: bn_copy(tmp3, tmp2)\n");
        #endif
        bn_copy(&tmp3, &tmp2);
        if (debug) printf("# 6\n");
        init_zero(&tmp2);
        bn_mod_inverse(&tmp2, &tmp3, p); // OK
        if (debug) printf("# 7\n");
        init_zero(&s);
        bn_mul(&tmp1, &tmp2, &s);
        bn_print("### s:", &s); // Debug OK
        if (debug) printf("# 8\n");
        init_zero(&tmp2);
        #ifdef debug_bn_copy
            printf("point_add: bn_copy(tmp2, s)\n");
        #endif
        bn_copy(&tmp2, &s);
        if (debug) printf("# 9\n"); // tmp2 OK
        init_zero(&s);
        bn_mod(&s, &tmp2, p);                 // s = (p2.y - p1.y) / (p2.x - p1.x) mod p
        if (debug) printf("# 10\n");
        init_zero(&tmp2);
        #ifdef debug_bn_copy
            printf("point_add: bn_copy(tmp2, s)\n");
        #endif
        bn_copy(&tmp2, &s);
        if (debug) printf("# 11\n");
        bn_mul(&s, &tmp2, &x3); // a * b = product // x3 = s^2
        if (debug) printf("# 12\n");
        init_zero(&tmp2);
        #ifdef debug_bn_copy
            printf("point_add: bn_copy(tmp2, x3)\n");
        #endif
        bn_copy(&tmp2, &x3);
        if (debug) printf("# 13\n");
        bn_sub(&x3, &tmp2, &p1->x); // result = a - b
        if (debug) printf("# 14\n");
        bn_sub(&x3, &x3, &p2->x);          // x3 = s^2 - p1.x - p2.x
        if (debug) printf("# 15\n");
        init_zero(&tmp2);
        #ifdef debug_bn_copy
            printf("point_add: bn_copy(tmp2, x3)\n");
        #endif
        bn_copy(&tmp2, &x3);
        if (debug) printf("# 16\n");
        bn_mod(&x3, &tmp2, p); // x3 = tmp2 mod p // OK
        if (debug) printf("# 17\n");
        bn_sub(&tmp1, &p1->x, &x3);
        if (debug) printf("# 18\n");
        bn_mul(&s, &tmp1, &y3); // a * b = product
        if (debug) printf("# 19\n");
        init_zero(&tmp2);
        #ifdef debug_bn_copy
            printf("point_add: bn_copy(tmp2, y3)\n");
        #endif
        bn_copy(&tmp2, &y3);
        if (debug) printf("# 20\n");
        bn_sub(&y3, &tmp2, &p1->y);          // y3 = s * (p1.x - x3) - p1.y
        if (debug) printf("# 21\n");
        init_zero(&tmp2);
        #ifdef debug_bn_copy
            printf("point_add: bn_copy(tmp2, y3)\n");
        #endif
        bn_copy(&tmp2, &y3);
        if (debug) printf("# 22\n");
        bn_mod(&y3, &tmp2, p);               // y3 = tmp2 mod p
        if (debug) printf("# 23\n");
    }

    if (debug) {
        printf("copy result to x3\n");
    }
    // Assign the computed coordinates to the result
    #ifdef debug_bn_copy
        printf("point_add: bn_copy(result->x, x3)\n");
    #endif
    bn_copy(&result->x, &x3);
    #ifdef debug_bn_copy
        printf("point_add: bn_copy(result->y, y3)\n");
    #endif
    bn_copy(&result->y, &y3);
    debug = 1;
    if (debug) {
        bn_print("<< x3: ", &x3);
        bn_print("<< y3: ", &y3);
    }

    return 0;
}

__device__ void init_point_at_infinity(EC_POINT_CUDA *P) {
    // For the x and y coordinates of P, we'll set the 'top' to 0,
    // which is our chosen convention for representing the point at infinity.

    init_zero(&P->x);
    init_zero(&P->y);

    P->x.top = 1; // No valid 'words' in the BIGNUM_CUDA representing x
    P->y.top = 1; // No valid 'words' in the BIGNUM_CUDA representing y
    
    // If 'd' arrays have been allocated, set them to zero as well.
    // memset could potentially be used for this if available and if 'd' is allocated.
    // Alternatively, if you use flags or other conventions for points at infinity,
    // set them accordingly here.
}

__device__ EC_POINT_CUDA ec_point_scalar_mul(
    EC_POINT_CUDA *point, 
    BIGNUM_CUDA *scalar, 
    BIGNUM_CUDA *curve_prime, 
    BIGNUM_CUDA *curve_a
    ) {
    #ifdef function_profiler
        unsigned long long start_time = clock64();
    #endif
    bool debug = 0;
    if (debug) {
        debug_printf("++ ec_point_scalar_mul ++\n");
        bn_print(">> point x: ", &point->x);
        bn_print(">> point y: ", &point->y);
        bn_print(">> scalar: ", scalar);
        bn_print(">> curve_prime: ", curve_prime);
        bn_print(">> curve_a: ", curve_a);
    }
    printf("++ ec_point_scalar_mul ++\n");
    printf("Input Point:\n");
    bn_print_no_fuse(">> point x: ", &point->x);
    bn_print_no_fuse(">> point y: ", &point->y);
    bn_print_no_fuse(">> Scalar: ", scalar);
    bn_print_no_fuse(">> curve_prime: ", curve_prime);
    bn_print_no_fuse(">> curve_a: ", curve_a);
    
    EC_POINT_CUDA current = *point; // This initializes the current point with the input point
    EC_POINT_CUDA result; // Initialize the result variable, which accumulates the result
    EC_POINT_CUDA tmp_result;
    EC_POINT_CUDA tmp_a;
    EC_POINT_CUDA tmp_b;                                     
    
    init_point_at_infinity(&result);                 // Initialize it to the point at infinity
    init_point_at_infinity(&tmp_result);                 // Initialize it to the point at infinity
    init_point_at_infinity(&tmp_a);                 // Initialize it to the point at infinity
    init_point_at_infinity(&tmp_b);                 // Initialize it to the point at infinity
    
    // Convert scalar BIGNUM_CUDA to an array of integers that's easy to iterate bit-wise
    unsigned int bits[256];                          // Assuming a 256-bit scalar
    bignum_to_bit_array(scalar, bits);    
    if (debug) printf("[D] Starting scalar multiplication loop\n");
    #ifdef use_jacobian_coordinates
        EC_POINT_JACOBIAN P_jacobian, Q_jacobian, resultAdd_jacobian;
    #endif

    for (int i = 0; i < 256; i++) {                 // Assuming 256-bit scalars        
        // if (debug) printf("[%d] step 0\n", i);
        if (bits[i]) {// If the i-th bit is set
            // if (debug) printf("[%d] step 1\n", i);
            init_point_at_infinity(&tmp_result);
            // if (debug) printf("[%d] step 2\n", i);
            
            // printf("\n\n[%d]\n", i);
            #ifdef use_jacobian_coordinates
                // bn_print_no_fuse(">> point_add current.x: ", &current.x);
                // bn_print_no_fuse(">> point_add current.y: ", &current.y);
                // bn_print_no_fuse(">> point_add result.x: ", &result.x);
                // bn_print_no_fuse(">> point_add result.y: ", &result.y);
                affine_to_jacobian(&result, &P_jacobian);
                affine_to_jacobian(&current, &Q_jacobian);
                // bn_print_no_fuse(">> point_add P_jacobian.x: ", &P_jacobian.X);
                // bn_print_no_fuse(">> point_add P_jacobian.y: ", &P_jacobian.Y);
                // bn_print_no_fuse(">> point_add P_jacobian.z: ", &P_jacobian.Z);
                // bn_print_no_fuse(">> point_add Q_jacobian.x: ", &Q_jacobian.X);
                // bn_print_no_fuse(">> point_add Q_jacobian.y: ", &Q_jacobian.Y);
                // bn_print_no_fuse(">> point_add Q_jacobian.z: ", &Q_jacobian.Z);
                point_add_jacobian(&resultAdd_jacobian, &Q_jacobian, &P_jacobian, curve_prime, curve_a);
                // bn_print_no_fuse("<< point_add resultAdd_jacobian.x: ", &resultAdd_jacobian.X);
                // bn_print_no_fuse("<< point_add resultAdd_jacobian.y: ", &resultAdd_jacobian.Y);
                // bn_print_no_fuse("<< point_add resultAdd_jacobian.z: ", &resultAdd_jacobian.Z);
                jacobian_to_affine(&resultAdd_jacobian, &result, curve_prime);
                // bn_print_no_fuse("<< point_add result.x: ", &result.x);
                // bn_print_no_fuse("<< point_add result.y: ", &result.y);
            #else
                // bn_print_no_fuse(">> point_add current.x: ", &current.x);
                // bn_print_no_fuse(">> point_add current.y: ", &current.y);
                // bn_print_no_fuse(">> point_add result.x: ", &result.x);
                // bn_print_no_fuse(">> point_add result.y: ", &result.y);
                point_add_affine(&tmp_result, &result, &current, curve_prime, curve_a);  // Add current to the result
                // bn_print_no_fuse("<< point_add tmp_result.x: ", &tmp_result.x);
                // bn_print_no_fuse("<< point_add tmp_result.y: ", &tmp_result.y);
                // if (debug) printf("[%d] step 3\n", i);
                init_point_at_infinity(&result); // Reset result
                // if (debug) printf("[%d] step 4\n", i);
                // #ifdef debug_bn_copy
                //     printf("ec_point_scalar_mul: bn_copy(result.x, tmp_result.x)\n");
                // #endif
                bn_copy(&result.x, &tmp_result.x);
                // if (debug) printf("[%d] step 5\n", i);
                // #ifdef debug_bn_copy
                //     printf("ec_point_scalar_mul: bn_copy(result.y, tmp_result.y)\n");
                // #endif
                bn_copy(&result.y, &tmp_result.y);   
            #endif
            // printf("[%d] ", i);
            // bn_print_no_fuse("point_add result.x: ", &result.x);
            // bn_print_no_fuse("point_add result.y: ", &result.y);
        }
        if (debug) printf("[%d] step 6\n", i);
        // init tmp_result
        init_point_at_infinity(&tmp_result);
        if (debug) printf("[%d] step 7\n", i);
        // init tmp_a
        init_point_at_infinity(&tmp_a);
        if (debug) printf("[%d] step 8\n", i);
        // init tmp_b
        init_point_at_infinity(&tmp_b);
        if (debug) printf("[%d] step 9\n", i);
        // Copy current to tmp_a
        #ifdef debug_bn_copy
            printf("ec_point_scalar_mul: bn_copy(tmp_a.x, current.x)\n");
        #endif
        bn_copy(&tmp_a.x, &current.x);
        if (debug) printf("[%d] step 10\n", i);
        #ifdef debug_bn_copy
            printf("ec_point_scalar_mul: bn_copy(tmp_a.y, current.y)\n");
        #endif
        bn_copy(&tmp_a.y, &current.y);
        if (debug) printf("[%d] step 11\n", i);
        // Copy current to tmp_b
        #ifdef debug_bn_copy
            printf("ec_point_scalar_mul: bn_copy(tmp_b.x, current.x)\n");
        #endif        
        #ifdef use_jacobian_coordinates
            affine_to_jacobian(&current, &Q_jacobian);
            jacobian_point_double(&resultAdd_jacobian, &Q_jacobian, curve_prime, curve_a);
            jacobian_to_affine(&resultAdd_jacobian, &current, curve_prime);
        #else
            bn_copy(&tmp_b.x, &current.x);
            if (debug) printf("[%d] step 12\n", i);
            #ifdef debug_bn_copy
                printf("ec_point_scalar_mul: bn_copy(tmp_b.y, current.y)\n");
            #endif
            bn_copy(&tmp_b.y, &current.y);
            // if (debug) printf("[%d] step 13\n", i);
            point_add_affine(&tmp_result, &tmp_a, &tmp_b, curve_prime, curve_a);  // Double current by adding to itself
            // if (debug) printf("[%d] step 14\n", i);
            // Copy tmp_result to current
            #ifdef debug_bn_copy
                printf("ec_point_scalar_mul: bn_copy(current.x, tmp_result.x)\n");
            #endif
            bn_copy(&current.x, &tmp_result.x);
            if (debug) printf("[%d] step 15\n", i);
            #ifdef debug_bn_copy
                printf("ec_point_scalar_mul: bn_copy(current.y, tmp_result.y)\n");
            #endif
            bn_copy(&current.y, &tmp_result.y);
        #endif
        
        if (debug) printf("[%d] passed\n", i);
    }    
    // Copy current to result
    if (debug) bn_print("3 result.x: ", &result.x);
    if (debug) bn_print("3 result.y: ", &result.y);
    bn_print_no_fuse("<< result.x: ", &result.x);
    bn_print_no_fuse("<< result.y: ", &result.y);
    printf("-- ec_point_scalar_mul --\n");
    #ifdef function_profiler
        record_function(FN_EC_POINT_SCALAR_MUL, start_time);
    #endif
    return result;
}

// Montgomery form of elliptic curve point multiplication ++

typedef struct {
    BIGNUM_CUDA N;     // The modulus
    BIGNUM_CUDA R;     // R = 2^(word_size * num_words)
    BIGNUM_CUDA Ri;    // R^(-1) mod N
    BIGNUM_CUDA R2;    // R^2 mod N
    BN_ULONG n0;       // -N^(-1) mod 2^word_size
} MONT_CTX_CUDA;

// Helper macros for word operations
#define WORD_BITS BN_ULONG_NUM_BITS
#define WORD_MASK ((BN_ULONG)(-1))

// Helper macros for bit operations (if not already defined)
#define BN_BITS2        BN_ULONG_NUM_BITS     // Number of bits in a word
#define BN_BYTES        (BN_BITS2 / 8)        // Number of bytes in a word
#define BN_BITS4        (BN_BITS2 / 2)        // Half the number of bits in a word
#define BN_MASK         ((BN_ULONG)(-1))      // All bits set
#define BN_MASK2        (BN_MASK >> BN_BITS4) // Lower half bits set

// Set bit n in a BIGNUM_CUDA
__device__ int bn_set_bit(BIGNUM_CUDA *a, int n) {
    int word_index = n / BN_BITS2;
    int bit_index = n % BN_BITS2;
    
    // Check if the word index is within bounds
    if (word_index >= MAX_BIGNUM_SIZE) {
        return 0; // Failure - bit position too large
    }
    
    // Expand the number if needed
    if (word_index >= a->top) {
        // Zero out any words between current top and new word
        for (int i = a->top; i < word_index; i++) {
            a->d[i] = 0;
        }
        a->top = word_index + 1;
    }
    
    // Set the bit using bitwise OR
    a->d[word_index] |= ((BN_ULONG)1 << bit_index);
    
    // Update top if necessary
    while (a->top > 0 && a->d[a->top - 1] == 0) {
        a->top--;
    }
    if (a->top == 0) {
        a->top = 1;
    }
    
    return 1; // Success
}

// Helper function to test if a bit is set (useful for debugging)
__device__ int bn_is_bit_set(const BIGNUM_CUDA *a, int n) {
    int word_index = n / BN_BITS2;
    int bit_index = n % BN_BITS2;
    
    // Check if the bit is beyond the number's current size
    if (word_index >= a->top) {
        return 0;
    }
    
    return (a->d[word_index] & ((BN_ULONG)1 << bit_index)) ? 1 : 0;
}

// Helper function to clear a bit (might be useful)
__device__ int bn_clear_bit(BIGNUM_CUDA *a, int n) {
    int word_index = n / BN_BITS2;
    int bit_index = n % BN_BITS2;
    
    // If the word index is beyond current size, bit is already clear
    if (word_index >= a->top) {
        return 1;
    }
    
    // Clear the bit using bitwise AND with inverted mask
    a->d[word_index] &= ~((BN_ULONG)1 << bit_index);
    
    // Update top if necessary
    while (a->top > 0 && a->d[a->top - 1] == 0) {
        a->top--;
    }
    if (a->top == 0) {
        a->top = 1;
    }
    
    return 1;
}

// Helper function to get the number of bits in a BIGNUM_CUDA
__device__ int bn_num_bits(const BIGNUM_CUDA *a) {
    if (a->top == 0) {
        return 0;
    }
    
    // Find the highest non-zero word
    int word_index = a->top - 1;
    while (word_index >= 0 && a->d[word_index] == 0) {
        word_index--;
    }
    
    if (word_index < 0) {
        return 0;
    }
    
    // Find the highest set bit in the highest non-zero word
    BN_ULONG word = a->d[word_index];
    int bit_count = word_index * BN_BITS2;
    
    while (word) {
        word >>= 1;
        bit_count++;
    }
    
    return bit_count;
}

// Example usage function
__device__ void test_bn_set_bit(BIGNUM_CUDA *a) {
    // Set some bits
    bn_set_bit(a, 0);    // Set least significant bit
    bn_set_bit(a, 63);   // Set bit 63 (assuming 64-bit words)
    bn_set_bit(a, 127);  // Set bit 127
    
    // Print the number in binary (for debugging)
    #ifdef debug_print
        printf("Number in binary: ");
        for (int i = bn_num_bits(a) - 1; i >= 0; i--) {
            printf("%d", bn_is_bit_set(a, i));
            if (i % 8 == 0) printf(" ");
        }
        printf("\n");
    #endif
}

// Helper function for single-word multiplication
__device__ void bn_mul_word_internal(BN_ULONG a, BN_ULONG b, BN_ULONG *hi, BN_ULONG *lo) {
    // Split a and b into high and low parts
    BN_ULONG a_hi = a >> (WORD_BITS/2);
    BN_ULONG a_lo = a & ((1ULL << (WORD_BITS/2)) - 1);
    BN_ULONG b_hi = b >> (WORD_BITS/2);
    BN_ULONG b_lo = b & ((1ULL << (WORD_BITS/2)) - 1);
    
    // Compute partial products
    BN_ULONG p0 = a_lo * b_lo;
    BN_ULONG p1 = a_lo * b_hi;
    BN_ULONG p2 = a_hi * b_lo;
    BN_ULONG p3 = a_hi * b_hi;
    
    // Combine partial products
    BN_ULONG middle = p1 + p2;
    if (middle < p1) p3 += 1ULL << (WORD_BITS/2);
    
    p3 += middle >> (WORD_BITS/2);
    middle = (middle << (WORD_BITS/2)) & WORD_MASK;
    p0 += middle;
    if (p0 < middle) p3++;
    
    *hi = p3;
    *lo = p0;
}

__device__ void mont_reduce(BIGNUM_CUDA *result, BIGNUM_CUDA *T, const MONT_CTX_CUDA *mont_ctx) {
    // T is a double-precision number (2× the size of regular numbers)
    // result will be a single-precision number
    
    const int N_words = mont_ctx->N.top;
    BN_ULONG carry = 0;
    BIGNUM_CUDA m;
    init_zero(&m);
    
    // Process each word of T
    for (int i = 0; i < N_words; i++) {
        // Calculate m = (T[0] * n0) mod 2^WORD_BITS
        // where n0 is precomputed -N^(-1) mod 2^WORD_BITS
        BN_ULONG u = (T->d[i] + carry) & WORD_MASK;
        BN_ULONG m_i = (u * mont_ctx->n0) & WORD_MASK;
        m.d[i] = m_i;
        
        // T = T + m*N, shifted right by one word
        BN_ULONG k = 0;  // Carry for multiplication
        carry = 0;       // Carry for addition
        
        for (int j = 0; j < N_words; j++) {
            // Multiply m_i by N[j]
            BN_ULONG hi, lo;
            bn_mul_word_internal(m_i, mont_ctx->N.d[j], &hi, &lo);
            
            // Add to T[i+j] with carries
            BN_ULONG t = T->d[i + j] + k;
            if (t < T->d[i + j]) hi++;
            t += lo;
            if (t < lo) hi++;
            T->d[i + j] = t;
            k = hi;
        }
        
        // Propagate carries
        for (int j = i + N_words; j < 2 * N_words && (k || carry); j++) {
            BN_ULONG t = T->d[j] + k + carry;
            carry = (t < T->d[j]) || (k && t == T->d[j]);
            T->d[j] = t;
            k = 0;
        }
    }
    
    // Right shift by N_words
    for (int i = 0; i < N_words; i++) {
        T->d[i] = T->d[i + N_words];
    }
    for (int i = N_words; i < 2 * N_words; i++) {
        T->d[i] = 0;
    }
    
    // Final reduction - if T >= N, subtract N
    if (bn_cmp(T, &mont_ctx->N) >= 0) {
        BIGNUM_CUDA tmp;
        init_zero(&tmp);
        bn_sub(&tmp, T, &mont_ctx->N);
        bn_copy(T, &tmp);
    }
    
    bn_copy(result, T);
}

// Complete Montgomery multiplication
__device__ void mont_mul(BIGNUM_CUDA *result, const BIGNUM_CUDA *a, const BIGNUM_CUDA *b, 
                        const MONT_CTX_CUDA *mont_ctx) {
    // T = a * b
    BIGNUM_CUDA T;
    init_zero(&T);
    bn_mul(a, b, &T);
    
    // Perform Montgomery reduction
    mont_reduce(result, &T, mont_ctx);
}

// Computes the extended GCD of a and b
// Returns gcd(a,b) and finds x,y such that ax + by = gcd(a,b)
// If x or y is NULL, that coefficient is not computed
__device__ void bn_extended_gcd(const BIGNUM_CUDA *a, const BIGNUM_CUDA *b, 
                               BIGNUM_CUDA *x, BIGNUM_CUDA *y, BIGNUM_CUDA *gcd) {
    BIGNUM_CUDA old_r, r;
    BIGNUM_CUDA old_s, s;
    BIGNUM_CUDA old_t, t;
    BIGNUM_CUDA quotient, temp1, temp2;
    
    // Initialize all temporary variables
    init_zero(&old_r);
    init_zero(&r);
    init_zero(&old_s);
    init_zero(&s);
    init_zero(&old_t);
    init_zero(&t);
    init_zero(&quotient);
    init_zero(&temp1);
    init_zero(&temp2);
    
    // Initialize starting values
    bn_copy(&old_r, a);     // old_r = a
    bn_copy(&r, b);         // r = b
    init_one(&old_s);       // old_s = 1
    init_zero(&s);          // s = 0
    init_zero(&old_t);      // old_t = 0
    init_one(&t);           // t = 1
    
    // While r ≠ 0
    while (!bn_is_zero(&r)) {
        // Compute quotient = old_r / r
        init_zero(&quotient);
        init_zero(&temp1);
        bn_div(&quotient, &temp1, &old_r, &r);
        
        // temp1 = quotient * r
        init_zero(&temp1);
        bn_mul(&quotient, &r, &temp1);
        
        // temp2 = old_r - temp1 = old_r - quotient * r
        init_zero(&temp2);
        bn_sub(&temp2, &old_r, &temp1);
        
        // old_r = r
        bn_copy(&old_r, &r);
        
        // r = temp2
        bn_copy(&r, &temp2);
        
        // Same for s
        // temp1 = quotient * s
        init_zero(&temp1);
        bn_mul(&quotient, &s, &temp1);
        
        // temp2 = old_s - temp1
        init_zero(&temp2);
        bn_sub(&temp2, &old_s, &temp1);
        
        // old_s = s
        bn_copy(&old_s, &s);
        
        // s = temp2
        bn_copy(&s, &temp2);
        
        // Same for t
        // temp1 = quotient * t
        init_zero(&temp1);
        bn_mul(&quotient, &t, &temp1);
        
        // temp2 = old_t - temp1
        init_zero(&temp2);
        bn_sub(&temp2, &old_t, &temp1);
        
        // old_t = t
        bn_copy(&old_t, &t);
        
        // t = temp2
        bn_copy(&t, &temp2);
    }
    
    // Set outputs
    if (gcd != NULL) {
        bn_copy(gcd, &old_r);
    }
    
    if (x != NULL) {
        bn_copy(x, &old_s);
        // Adjust sign if necessary
        if (a->neg) {
            x->neg = !x->neg;
        }
    }
    
    if (y != NULL) {
        bn_copy(y, &old_t);
        // Adjust sign if necessary
        if (b->neg) {
            y->neg = !y->neg;
        }
    }
}

// Helper function to verify the result
__device__ int verify_extended_gcd(const BIGNUM_CUDA *a, const BIGNUM_CUDA *b,
                                 const BIGNUM_CUDA *x, const BIGNUM_CUDA *y,
                                 const BIGNUM_CUDA *gcd) {
    BIGNUM_CUDA temp1, temp2, temp3;
    init_zero(&temp1);
    init_zero(&temp2);
    init_zero(&temp3);
    
    // Calculate ax
    bn_mul(a, x, &temp1);
    
    // Calculate by
    bn_mul(b, y, &temp2);
    
    // Calculate ax + by
    bn_add(&temp3, &temp1, &temp2);
    
    // Compare with gcd
    return (bn_cmp(&temp3, gcd) == 0);
}

// Example usage function
__device__ void test_extended_gcd() {
    BIGNUM_CUDA a, b, x, y, gcd;
    init_zero(&a);
    init_zero(&b);
    init_zero(&x);
    init_zero(&y);
    init_zero(&gcd);
    
    // Set test values
    bn_set_word(&a, 240);  // a = 240
    bn_set_word(&b, 46);   // b = 46
    
    // Compute extended GCD
    bn_extended_gcd(&a, &b, &x, &y, &gcd);
    
    #ifdef debug_print
        printf("Extended GCD of 240 and 46:\n");
        bn_print("GCD: ", &gcd);
        bn_print("x: ", &x);
        bn_print("y: ", &y);
        
        if (verify_extended_gcd(&a, &b, &x, &y, &gcd)) {
            printf("Verification passed: ax + by = gcd(a,b)\n");
        } else {
            printf("Verification failed!\n");
        }
    #endif
}

// Helper function for modular inverse using extended GCD
__device__ int bn_mod_inverse_gcd(BIGNUM_CUDA *result, const BIGNUM_CUDA *a, const BIGNUM_CUDA *m) {
    BIGNUM_CUDA x, y, gcd;
    init_zero(&x);
    init_zero(&y);
    init_zero(&gcd);
    
    // Compute extended GCD
    bn_extended_gcd(a, m, &x, &y, &gcd);
    
    // Check if GCD is 1 (numbers are coprime)
    if (!bn_is_one(&gcd)) {
        return 0;  // No modular inverse exists
    }
    
    // Make sure result is positive
    if (x.neg) {
        bn_add(&x, &x, m);
    }
    
    bn_copy(result, &x);
    return 1;
}

// Initialize Montgomery context
__device__ void mont_ctx_init(MONT_CTX_CUDA *ctx, const BIGNUM_CUDA *N) {
    // Copy modulus
    bn_copy(&ctx->N, N);
    
    // Calculate R = 2^(word_size * num_words)
    init_zero(&ctx->R);
    int num_bits = N->top * WORD_BITS;
    bn_set_bit(&ctx->R, num_bits);
    
    // Calculate R^2 mod N
    init_zero(&ctx->R2);
    BIGNUM_CUDA tmp;
    init_zero(&tmp);
    bn_mul(&ctx->R, &ctx->R, &tmp);
    bn_mod(&ctx->R2, &tmp, N);
    
    // Calculate R^(-1) mod N
    init_zero(&ctx->Ri);
    BIGNUM_CUDA one;
    init_one(&one);
    BIGNUM_CUDA tmp_gcd;
    init_zero(&tmp_gcd);
    bn_extended_gcd(&ctx->R, N, &ctx->Ri, NULL, &tmp_gcd);
    if (ctx->Ri.neg) {
        bn_add(&ctx->Ri, &ctx->Ri, N);
    }
    
    // Calculate n0 = -N^(-1) mod 2^WORD_BITS
    BIGNUM_CUDA N_prime;
    init_zero(&N_prime);
    BN_ULONG n0 = 1;
    for (int i = 0; i < WORD_BITS; i++) {
        BN_ULONG t = n0 * N->d[0];
        if (t & ((BN_ULONG)1 << i)) {
            n0 |= (BN_ULONG)1 << i;
        }
    }
    ctx->n0 = (BN_ULONG)0 - n0;  // Two's complement
}

// Helper macro for checking the least significant bit of a word
#define BN_LSBIT(w) ((w) & 1)

// Right shift by 1 bit
__device__ void bn_rshift1(BIGNUM_CUDA *a) {
    BN_ULONG carry = 0;
    BN_ULONG next_carry;
    int i;
    
    if (a->top == 0) return;  // Nothing to shift
    
    // Process each word from most significant to least significant
    for (i = a->top - 1; i >= 0; i--) {
        // Save the least significant bit for the next word's carry
        next_carry = BN_LSBIT(a->d[i]);
        
        // Shift the current word right by 1 and add previous carry
        a->d[i] = (a->d[i] >> 1) | (carry << (BN_ULONG_NUM_BITS - 1));
        
        // Update carry for next iteration
        carry = next_carry;
    }
    
    // Update top (remove leading zero words)
    while (a->top > 1 && a->d[a->top - 1] == 0) {
        a->top--;
    }
}

// Helper function to shift right by N bits
__device__ void bn_rshift(BIGNUM_CUDA *a, int n) {
    if (n <= 0) return;  // No shift needed
    if (a->top == 0) return;  // Number is zero
    
    // Calculate word offset and bit offset
    int word_shift = n / BN_ULONG_NUM_BITS;
    int bit_shift = n % BN_ULONG_NUM_BITS;
    
    // If word_shift >= a->top, result is 0
    if (word_shift >= a->top) {
        a->top = 1;
        a->d[0] = 0;
        return;
    }
    
    // Perform word shift
    if (word_shift > 0) {
        int i;
        for (i = 0; i < a->top - word_shift; i++) {
            a->d[i] = a->d[i + word_shift];
        }
        for (i = a->top - word_shift; i < a->top; i++) {
            a->d[i] = 0;
        }
        a->top -= word_shift;
    }
    
    // Perform bit shift
    if (bit_shift > 0) {
        BN_ULONG carry = 0;
        int i;
        
        for (i = a->top - 1; i >= 0; i--) {
            BN_ULONG next_carry = a->d[i] << (BN_ULONG_NUM_BITS - bit_shift);
            a->d[i] = (a->d[i] >> bit_shift) | carry;
            carry = next_carry;
        }
        
        // Update top (remove leading zero words)
        while (a->top > 1 && a->d[a->top - 1] == 0) {
            a->top--;
        }
    }
}

// Helper function to shift left by 1 bit (might be useful)
__device__ void bn_lshift1(BIGNUM_CUDA *a) {
    BN_ULONG carry = 0;
    BN_ULONG next_carry;
    int i;
    
    // Check if we need to grow the number
    if ((a->d[a->top - 1] & (((BN_ULONG)1) << (BN_ULONG_NUM_BITS - 1))) != 0) {
        // Highest bit is set, need to add a new word
        if (a->top >= MAX_BIGNUM_SIZE) return;  // Cannot grow further
        a->d[a->top] = 0;
        a->top++;
    }
    
    // Process each word from least significant to most significant
    for (i = 0; i < a->top; i++) {
        // Save the most significant bit for the next word's carry
        next_carry = a->d[i] >> (BN_ULONG_NUM_BITS - 1);
        
        // Shift the current word left by 1 and add previous carry
        a->d[i] = (a->d[i] << 1) | carry;
        
        // Update carry for next iteration
        carry = next_carry;
    }
}

// Helper function for Montgomery inversion
__device__ void mont_inv(BIGNUM_CUDA *result, const BIGNUM_CUDA *a, const MONT_CTX_CUDA *mont_ctx) {
    // Calculate a^(-1) * R mod N using binary extended GCD algorithm
    // This is more efficient than converting out of Montgomery form,
    // inverting, and converting back
    
    BIGNUM_CUDA u, v, x1, x2;
    init_zero(&u);
    init_zero(&v);
    init_zero(&x1);
    init_zero(&x2);
    
    bn_copy(&u, a);
    bn_copy(&v, &mont_ctx->N);
    init_one(&x1);
    init_zero(&x2);
    
    while (!bn_is_zero(&u)) {
        while (!bn_is_bit_set(&u, 0)) {  // u is even
            bn_rshift1(&u);
            if (bn_is_bit_set(&x1, 0))
                bn_add(&x1, &x1, &mont_ctx->N);
            bn_rshift1(&x1);
        }
        
        while (!bn_is_bit_set(&v, 0)) {  // v is even
            bn_rshift1(&v);
            if (bn_is_bit_set(&x2, 0))
                bn_add(&x2, &x2, &mont_ctx->N);
            bn_rshift1(&x2);
        }
        
        if (bn_cmp(&u, &v) >= 0) {
            bn_sub(&u, &u, &v);
            if (bn_cmp(&x1, &x2) < 0)
                bn_add(&x1, &x1, &mont_ctx->N);
            bn_sub(&x1, &x1, &x2);
        } else {
            bn_sub(&v, &v, &u);
            if (bn_cmp(&x2, &x1) < 0)
                bn_add(&x2, &x2, &mont_ctx->N);
            bn_sub(&x2, &x2, &x1);
        }
    }
    
    bn_copy(result, &x2);
}

__device__ EC_POINT_CUDA ec_point_scalar_mul_montgomery(
    EC_POINT_CUDA *point, 
    BIGNUM_CUDA *scalar,
    const MONT_CTX_CUDA *mont_ctx) {
    
    bool debug = 0;
    if (debug) {
        printf("++ ec_point_scalar_mul_montgomery ++\n");
        bn_print(">> point x: ", &point->x);
        bn_print(">> point y: ", &point->y);
        bn_print(">> scalar: ", scalar);
    }
    
    // Convert input point to Montgomery form
    EC_POINT_CUDA current;
    mont_mul(&current.x, &point->x, &mont_ctx->R2, mont_ctx); // x * R mod N
    mont_mul(&current.y, &point->y, &mont_ctx->R2, mont_ctx); // y * R mod N
    
    EC_POINT_CUDA result;
    init_point_at_infinity(&result);
    mont_mul(&result.x, &result.x, &mont_ctx->R2, mont_ctx); // Convert infinity point to Montgomery form
    mont_mul(&result.y, &result.y, &mont_ctx->R2, mont_ctx);
    
    // Temporary points for calculations
    EC_POINT_CUDA tmp_result, tmp_a, tmp_b;
    
    // Convert scalar to bit array
    unsigned int bits[256];
    bignum_to_bit_array(scalar, bits);
    
    for (int i = 0; i < 256; i++) {
        if (bits[i]) {
            // Point addition in Montgomery form
            if (!point_is_at_infinity(&result)) {
                // Calculate slope in Montgomery form
                BIGNUM_CUDA slope, dx, dy;
                init_zero(&slope);
                init_zero(&dx);
                init_zero(&dy);
                
                if (bn_cmp(&current.x, &result.x) == 0 && bn_cmp(&current.y, &result.y) == 0) {
                    // Point doubling slope calculation
                    BIGNUM_CUDA tmp1, tmp2, two, three;
                    init_zero(&tmp1);
                    init_zero(&tmp2);
                    bn_set_word(&two, 2);
                    bn_set_word(&three, 3);
                    
                    // 3x^2 in Montgomery form
                    mont_mul(&tmp1, &current.x, &current.x, mont_ctx);
                    mont_mul(&tmp2, &tmp1, &three, mont_ctx);
                    
                    // 2y in Montgomery form
                    mont_mul(&dy, &current.y, &two, mont_ctx);
                    
                    // Calculate inverse of 2y using Montgomery inverse
                    BIGNUM_CUDA dy_inv;
                    init_zero(&dy_inv);
                    mont_inv(&dy_inv, &dy, mont_ctx);
                    
                    // Final slope calculation
                    mont_mul(&slope, &tmp2, &dy_inv, mont_ctx);
                } else {
                    // Point addition slope calculation
                    bn_sub(&dy, &current.y, &result.y);
                    bn_sub(&dx, &current.x, &result.x);
                    
                    // Convert dx and dy to Montgomery form
                    BIGNUM_CUDA dx_mont, dy_mont;
                    init_zero(&dx_mont);
                    init_zero(&dy_mont);
                    mont_mul(&dx_mont, &dx, &mont_ctx->R2, mont_ctx);
                    mont_mul(&dy_mont, &dy, &mont_ctx->R2, mont_ctx);
                    
                    // Calculate inverse of dx using Montgomery inverse
                    BIGNUM_CUDA dx_inv;
                    init_zero(&dx_inv);
                    mont_inv(&dx_inv, &dx_mont, mont_ctx);
                    
                    // Final slope calculation
                    mont_mul(&slope, &dy_mont, &dx_inv, mont_ctx);
                }
                
                // Calculate new x coordinate
                BIGNUM_CUDA x3, tmp;
                init_zero(&x3);
                init_zero(&tmp);
                
                mont_mul(&tmp, &slope, &slope, mont_ctx);  // s^2
                bn_sub(&x3, &tmp, &current.x);            // s^2 - x1
                bn_sub(&x3, &x3, &result.x);              // s^2 - x1 - x2
                
                // Calculate new y coordinate
                BIGNUM_CUDA y3;
                init_zero(&y3);
                
                bn_sub(&tmp, &result.x, &x3);             // x1 - x3
                mont_mul(&tmp, &slope, &tmp, mont_ctx);    // s(x1 - x3)
                bn_sub(&y3, &tmp, &result.y);             // s(x1 - x3) - y1
                
                // Update result
                bn_copy(&result.x, &x3);
                bn_copy(&result.y, &y3);
            } else {
                // If result is infinity, just copy current point
                bn_copy(&result.x, &current.x);
                bn_copy(&result.y, &current.y);
            }
        }
        
        // Point doubling for next iteration
        if (i < 255) {  // No need to double after the last bit
            if (!point_is_at_infinity(&current)) {
                // Calculate slope for doubling
                BIGNUM_CUDA slope, tmp1, tmp2, two, three;
                init_zero(&slope);
                init_zero(&tmp1);
                init_zero(&tmp2);
                bn_set_word(&two, 2);
                bn_set_word(&three, 3);
                
                // 3x^2 in Montgomery form
                mont_mul(&tmp1, &current.x, &current.x, mont_ctx);
                mont_mul(&tmp2, &tmp1, &three, mont_ctx);
                
                // 2y in Montgomery form
                BIGNUM_CUDA dy;
                init_zero(&dy);
                mont_mul(&dy, &current.y, &two, mont_ctx);
                
                // Calculate inverse of 2y using Montgomery inverse
                BIGNUM_CUDA dy_inv;
                init_zero(&dy_inv);
                mont_inv(&dy_inv, &dy, mont_ctx);
                
                // Final slope calculation
                mont_mul(&slope, &tmp2, &dy_inv, mont_ctx);
                
                // Calculate new x coordinate
                BIGNUM_CUDA x3;
                init_zero(&x3);
                mont_mul(&tmp1, &slope, &slope, mont_ctx);  // s^2
                bn_sub(&x3, &tmp1, &current.x);            // s^2 - x1
                bn_sub(&x3, &x3, &current.x);              // s^2 - 2x1
                
                // Calculate new y coordinate
                BIGNUM_CUDA y3;
                init_zero(&y3);
                bn_sub(&tmp1, &current.x, &x3);            // x1 - x3
                mont_mul(&tmp2, &slope, &tmp1, mont_ctx);   // s(x1 - x3)
                bn_sub(&y3, &tmp2, &current.y);            // s(x1 - x3) - y1
                
                // Update current point
                bn_copy(&current.x, &x3);
                bn_copy(&current.y, &y3);
            }
        }
    }
    
    // Convert result back from Montgomery form
    EC_POINT_CUDA final_result;
    BIGNUM_CUDA one;
    init_one(&one);
    mont_mul(&final_result.x, &result.x, &one, mont_ctx);  // x / R mod N
    mont_mul(&final_result.y, &result.y, &one, mont_ctx);  // y / R mod N
    
    return final_result;
}

// Global or device-side context initialization
__device__ MONT_CTX_CUDA curve_mont_ctx;

// Initialize the Montgomery context for curve parameters
__device__ void init_curve_montgomery_context(BIGNUM_CUDA *CURVE_P, BIGNUM_CUDA *CURVE_A) {
    // Initialize Montgomery context with the curve prime
    mont_ctx_init(&curve_mont_ctx, CURVE_P);
    
    // Store curve parameter A in Montgomery form if needed for point operations
    BIGNUM_CUDA A_mont;
    init_zero(&A_mont);
    mont_mul(&A_mont, CURVE_A, &curve_mont_ctx.R2, &curve_mont_ctx);
}

// Montgomery form of elliptic curve point multiplication --