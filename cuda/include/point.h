#include "jacobian_point.h"

// __device__ bool compute_mont_nprime(BIGNUM_CUDA *n_prime, const BIGNUM_CUDA *n, const BIGNUM_CUDA *R);
// __device__ void bn_mod_mul_montgomery(const BIGNUM_CUDA *a, const BIGNUM_CUDA *b, const BIGNUM_CUDA *n, BIGNUM_CUDA * __restrict__ result_of_multiplication);

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
        bn_print_no_fuse(">> scalar: ", scalar);
        bn_print_no_fuse(">> point x: ", &point->x);
        bn_print_no_fuse(">> point y: ", &point->y);        
        bn_print_no_fuse(">> curve_prime: ", curve_prime);
        bn_print_no_fuse(">> curve_a: ", curve_a);
    }
    printf("++ ec_point_scalar_mul ++\n");
    bn_print_no_fuse(">> Scalar: ", scalar);
    bn_print_no_fuse(">> point x: ", &point->x);
    bn_print_no_fuse(">> point y: ", &point->y);
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
        // printf("i: %d\n", i);
        // bn_print_no_fuse("point_add result.x: ", &result.x);
        // bn_print_no_fuse("point_add result.y: ", &result.y);
        // break; // TODO: Remove this break
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

// #define BN_MASK2        (BN_MASK >> BN_BITS4) // Lower half bits set

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

// ec_point_scalar_mul montgomery ++
// Add this structure to store Montgomery context
typedef struct {
    BIGNUM_CUDA R;       // Montgomery radix (R = 2^k where k is the bit length of n)
    BIGNUM_CUDA n;       // The modulus
    BIGNUM_CUDA n_prime; // -n^(-1) mod R
    BIGNUM_CUDA R2;      // R^2 mod n (used for Montgomery conversion)
    BIGNUM_CUDA one;     // 1 in Montgomery form (R mod n)
} MONT_CTX_CUDA;

// Montgomery initialization for curve parameters
__device__ bool init_curve_montgomery_context(const BIGNUM_CUDA *curve_p, const BIGNUM_CUDA *curve_a, MONT_CTX_CUDA *ctx) {
    bool debug = false;
    if (debug) {
        printf("++ init_curve_montgomery_context ++\n");
        bn_print_no_fuse(">> curve_p: ", curve_p);
        bn_print_no_fuse(">> curve_a: ", curve_a);
    }    
    if (bn_is_zero(curve_p)) {
        printf("Error: curve modulus cannot be zero\n");
        return false;
    }

    // MONT_CTX_CUDA ctx;
    
    // Initialize values
    init_zero(&ctx->R);
    init_zero(&ctx->n);
    init_zero(&ctx->n_prime);
    init_zero(&ctx->R2);
    init_zero(&ctx->one);

    // Set modulus
    bn_copy(&ctx->n, curve_p);

    // Calculate R = 2^k where k is the bit length of n
    int k = bn_bit_length(curve_p);
    if (k == 0) {
        printf("Error: invalid curve modulus bit length\n");
        return false;
    }
    bn_set_word(&ctx->R, 1);
    left_shift(&ctx->R, k);

    // Calculate n' = -n^(-1) mod R
    // compute_mont_nprime(&ctx->n_prime, curve_p, &ctx->R);
    // Calculate n' = -n^(-1) mod R
    if (!compute_mont_nprime(&ctx->n_prime, curve_p, &ctx->R)) {
        printf("Error: Could not compute n_prime for curve context\n");
        return false;
    }

    // Calculate R^2 mod n
    bn_mul(&ctx->R, &ctx->R, &ctx->R2);  // R^2
    bn_mod(&ctx->R2, &ctx->R2, curve_p); // R^2 mod n

    // Calculate 1 in Montgomery form (R mod n)
    bn_mod(&ctx->one, &ctx->R, curve_p);
    return true;
}

// Convert point to Montgomery form
__device__ void point_to_montgomery(EC_POINT_CUDA *result, const EC_POINT_CUDA *p, const MONT_CTX_CUDA *ctx) {
    BIGNUM_CUDA rx, ry;
    init_zero(&rx);
    init_zero(&ry);
    // Convert x coordinate
    // bn_mod_mul_montgomery(&p->x, &ctx->R2, &ctx->n, &result->x);
    // bn_mod_mul_montgomery(&p->x, &ctx->R, &ctx->n, &rx);
    bn_mod_mul_montgomery(&p->x, &ctx->R2, &ctx->n, &rx);
    bn_copy(&result->x, &rx);
    
    // Convert y coordinate
    // bn_mod_mul_montgomery(&p->y, &ctx->R2, &ctx->n, &result->y);
    // bn_mod_mul_montgomery(&p->y, &ctx->R, &ctx->n, &ry);
    bn_mod_mul_montgomery(&p->y, &ctx->R2, &ctx->n, &ry);
    bn_copy(&result->y, &ry);
}

// Convert point from Montgomery form
__device__ void point_from_montgomery(EC_POINT_CUDA *result, const EC_POINT_CUDA *p, const MONT_CTX_CUDA *ctx) {
    // Create a Montgomery representation of 1
    BIGNUM_CUDA one;
    init_zero(&one);
    bn_set_word(&one, 1);

    // Convert x coordinate back
    bn_mod_mul_montgomery(&p->x, &one, &ctx->n, &result->x);
    
    // Convert y coordinate back
    bn_mod_mul_montgomery(&p->y, &one, &ctx->n, &result->y);
}

// Montgomery point addition in Montgomery form
__device__ void point_add_montgomery(
    EC_POINT_CUDA *result, 
    EC_POINT_CUDA *p1, 
    EC_POINT_CUDA *p2, 
    const BIGNUM_CUDA *curve_p,
    const BIGNUM_CUDA *curve_a,
    const MONT_CTX_CUDA *ctx
) {
    // Handle point at infinity cases
    if (point_is_at_infinity(p1)) {
        copy_point(result, p2);
        return;
    }
    if (point_is_at_infinity(p2)) {
        copy_point(result, p1);
        return;
    }

    // Initialize temporary variables
    BIGNUM_CUDA s, x3, y3, tmp1, tmp2, tmp3, tmp4;
    init_zero(&s);
    init_zero(&x3);
    init_zero(&y3);
    init_zero(&tmp1);
    init_zero(&tmp2);
    init_zero(&tmp3);
    init_zero(&tmp4);

    // Convert constants to Montgomery form
    BIGNUM_CUDA two, three, two_mont, three_mont;
    init_zero(&two);
    init_zero(&three);
    init_zero(&two_mont);
    init_zero(&three_mont);

    bn_set_word(&two, 2);
    bn_set_word(&three, 3);

    // Convert constants to Montgomery form
    bn_mod_mul_montgomery(&two, &ctx->R2, curve_p, &two_mont);
    bn_mod_mul_montgomery(&three, &ctx->R2, curve_p, &three_mont);

    // Case 1: P1 = P2 and y1 = -y2
    if (bn_cmp(&p1->x, &p2->x) == 0) {
        if (bn_cmp(&p1->y, &p2->y) != 0) {
            set_point_at_infinity(result);
            return;
        }

        // Point doubling
        bn_mod_mul_montgomery(&p1->x, &p1->x, curve_p, &tmp1);      // tmp1 = x₁²
        bn_mod_mul_montgomery(&tmp1, &three_mont, curve_p, &tmp2);  // tmp2 = 3x₁²

        // tmp2 = 3x₁² + a (since a=0, we can skip adding a)

        bn_mod_mul_montgomery(&p1->y, &two_mont, curve_p, &tmp3);   // tmp3 = 2y₁
        bn_mod_inverse(&tmp4, &tmp3, curve_p);                      // tmp4 = (2y₁)⁻¹

        bn_mod_mul_montgomery(&tmp2, &tmp4, curve_p, &s);           // s = (3x₁²)/(2y₁)

    } else {
        // Regular point addition
        bn_mod_sub(&tmp1, &p2->y, &p1->y, curve_p);                 // tmp1 = y₂ - y₁
        bn_mod_sub(&tmp2, &p2->x, &p1->x, curve_p);                 // tmp2 = x₂ - x₁
        bn_mod_inverse(&tmp3, &tmp2, curve_p);                      // tmp3 = (x₂ - x₁)⁻¹
        bn_mod_mul_montgomery(&tmp1, &tmp3, curve_p, &s);           // s = (y₂ - y₁)/(x₂ - x₁)
    }

    // x₃ = s² - x₁ - x₂
    bn_mod_mul_montgomery(&s, &s, curve_p, &tmp1);                  // tmp1 = s²
    bn_mod_sub(&tmp2, &tmp1, &p1->x, curve_p);                      // tmp2 = s² - x₁
    bn_mod_sub(&x3, &tmp2, &p2->x, curve_p);                        // x₃ = s² - x₁ - x₂

    // y₃ = s(x₁ - x₃) - y₁
    bn_mod_sub(&tmp1, &p1->x, &x3, curve_p);                        // tmp1 = x₁ - x₃
    bn_mod_mul_montgomery(&s, &tmp1, curve_p, &tmp2);               // tmp2 = s(x₁ - x₃)
    bn_mod_sub(&y3, &tmp2, &p1->y, curve_p);                        // y₃ = s(x₁ - x₃) - y₁

    // Set result coordinates
    bn_copy(&result->x, &x3);
    bn_copy(&result->y, &y3);
}

__device__ void point_add_montgomery_x(
    EC_POINT_CUDA *result, 
    EC_POINT_CUDA *p1, 
    EC_POINT_CUDA *p2, 
    const BIGNUM_CUDA *curve_p,
    const BIGNUM_CUDA *curve_a,
    const MONT_CTX_CUDA *ctx
    ) {
    // Handle point at infinity cases
    if (point_is_at_infinity(p1)) {
        copy_point(result, p2);
        return;
    }
    if (point_is_at_infinity(p2)) {
        copy_point(result, p1);
        return;
    }

    // Initialize temporary variables
    BIGNUM_CUDA s, x3, y3, tmp1, tmp2, tmp3, tmp4;
    init_zero(&s);
    init_zero(&x3);
    init_zero(&y3);
    init_zero(&tmp1);
    init_zero(&tmp2);
    init_zero(&tmp3);
    init_zero(&tmp4);

    // Case 1: P1 = P2 and y1 = -y2 (including P1 = P2 = point at infinity)
    if (bn_cmp(&p1->x, &p2->x) == 0) {
        if (bn_cmp(&p1->y, &p2->y) != 0) {
            // Points are inverses of each other
            set_point_at_infinity(result);
            return;
        }

        // Point doubling case (P1 = P2)
        // s = (3x₁² + a) / 2y₁

        // Calculate 3x₁²
        bn_mod_mul_montgomery(&p1->x, &p1->x, curve_p, &tmp1);    // x₁²
        BIGNUM_CUDA three;
        init_zero(&three);
        bn_set_word(&three, 3);
        bn_mod_mul_montgomery(&tmp1, &three, curve_p, &tmp2);     // 3x₁²

        // Add curve parameter 'a' (in Montgomery form)
        // bn_add(&tmp2, &tmp2, curve_a);                           // 3x₁² + a
        init_zero(&tmp4);
        // bn_print_no_fuse("### tmp2: ", &tmp2);
        // bn_print_no_fuse("### curve_a: ", curve_a);
        bn_add(&tmp4, &tmp2, curve_a);                           // 3x₁² + a
        bn_copy(&tmp2, &tmp4);

        init_zero(&tmp4);
        // bn_mod(&tmp2, &tmp2, curve_p); // TODO: Avoid of collizion between tmp2 and tmp2
        bn_mod(&tmp4, &tmp2, curve_p);
        bn_copy(&tmp2, &tmp4);

        // Calculate 2y₁
        bn_mod_mul_montgomery(&p1->y, &ctx->R2, curve_p, &tmp1);  // Convert y₁ to Montgomery form
        BIGNUM_CUDA two;
        init_zero(&two);
        bn_set_word(&two, 2);
        bn_mod_mul_montgomery(&tmp1, &two, curve_p, &tmp3);       // 2y₁

        // Calculate final slope
        bn_mod_inverse(&tmp1, &tmp3, curve_p);                    // 1/2y₁
        bn_mod_mul_montgomery(&tmp2, &tmp1, curve_p, &s);         // s = (3x₁² + a)/2y₁
    } else {
        // Regular point addition case
        // s = (y₂ - y₁)/(x₂ - x₁)

        // Calculate y₂ - y₁
        bn_mod_mul_montgomery(&p2->y, &ctx->one, curve_p, &tmp1);
        bn_mod_mul_montgomery(&p1->y, &ctx->one, curve_p, &tmp2);
        bn_sub(&tmp1, &tmp1, &tmp2);    // TODO: Check for colllizion
        bn_mod(&tmp1, &tmp1, curve_p);  // Ensure result is properly reduced // TODO: Check for colllizion

        // Calculate x₂ - x₁
        bn_mod_mul_montgomery(&p2->x, &ctx->one, curve_p, &tmp2);
        bn_mod_mul_montgomery(&p1->x, &ctx->one, curve_p, &tmp3);
        bn_sub(&tmp2, &tmp2, &tmp3);// TODO: Check for colllizion
        bn_mod(&tmp2, &tmp2, curve_p);// TODO: Check for colllizion

        // Calculate slope
        bn_mod_inverse(&tmp3, &tmp2, curve_p);
        bn_mod_mul_montgomery(&tmp1, &tmp3, curve_p, &s);
    }

    // Calculate x₃ = s² - x₁ - x₂
    bn_mod_mul_montgomery(&s, &s, curve_p, &tmp1);                // s²
    bn_sub(&tmp1, &tmp1, &p1->x);   // TODO: Check for colllizion                             // s² - x₁
    bn_sub(&tmp1, &tmp1, &p2->x);     // TODO: Check for colllizion                           // s² - x₁ - x₂
    bn_mod(&x3, &tmp1, curve_p);

    // Calculate y₃ = s(x₁ - x₃) - y₁
    bn_sub(&p1->x, &p1->x, &x3);                                 // x₁ - x₃
    bn_mod_mul_montgomery(&s, &p1->x, curve_p, &tmp1);           // s(x₁ - x₃)
    bn_sub(&tmp1, &tmp1, &p1->y);  // TODO: Check for colllizion                              // s(x₁ - x₃) - y₁
    bn_mod(&y3, &tmp1, curve_p);

    // Set result coordinates
    bn_copy(&result->x, &x3);
    bn_copy(&result->y, &y3);
}

// Main Montgomery scalar multiplication function
__device__ void ec_point_scalar_mul_montgomery(
    EC_POINT_CUDA *point, 
    BIGNUM_CUDA *scalar,
    const MONT_CTX_CUDA *ctx,
    EC_POINT_CUDA *final_result
    ) {
    bool debug = true;
    if (debug) {
        printf("++ ec_point_scalar_mul_montgomery ++\n");
        bn_print_no_fuse(">> scalar: ", scalar);
        bn_print_no_fuse(">> point.x: ", &point->x);
        bn_print_no_fuse(">> point.y: ", &point->y);
        bn_print_no_fuse(">> ctx->R: ", &ctx->R);
        bn_print_no_fuse(">> ctx->n: ", &ctx->n);
        bn_print_no_fuse(">> ctx->n_prime: ", &ctx->n_prime);
        bn_print_no_fuse(">> ctx->R2: ", &ctx->R2);
        bn_print_no_fuse(">> ctx->one: ", &ctx->one);
    }
    EC_POINT_CUDA result;
    init_point_at_infinity(&result);
    
    // Convert input point to Montgomery form
    EC_POINT_CUDA current;
    point_to_montgomery(&current, point, ctx);

    // Convert bits of scalar to array
    unsigned int bits[256];
    bignum_to_bit_array(scalar, bits);

    BIGNUM_CUDA curve_a;
    init_zero(&curve_a); // Assuming curve_a is zero for the curve used

    // Double-and-add algorithm using Montgomery arithmetic
    for (int i = 255; i >= 0; i--) {
        if (!point_is_at_infinity(&result)) {
            EC_POINT_CUDA temp_result;
            point_add_montgomery(&temp_result, &result, &result, &ctx->n, &curve_a, ctx);
            copy_point(&result, &temp_result);
        }

        if (bits[i]) {
            if (point_is_at_infinity(&result)) {
                copy_point(&result, &current);
            } else {
                EC_POINT_CUDA temp_result;
                point_add_montgomery(&temp_result, &result, &current, &ctx->n, &curve_a, ctx);
                copy_point(&result, &temp_result);
            }
        }
    }

    // Convert result back from Montgomery form
    point_from_montgomery(final_result, &result, ctx);
    if (debug) {
        bn_print_no_fuse("<< final_result.x: ", &final_result->x);
        bn_print_no_fuse("<< final_result.y: ", &final_result->y);
        printf("-- ec_point_scalar_mul_montgomery --\n");
    }
}
// ec_point_scalar_mul montgomery --