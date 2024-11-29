#include "jacobian_point.h"

#define WINDOW_SIZE 5
#define MAX_WNAF_LENGTH 256  // Adjust as per your needs
#define NUM_PRECOMPUTED_POINTS (1 << (WINDOW_SIZE - 1))

typedef struct ec_group_st_cuda {
    BIGNUM_CUDA field;  // Prime field modulus p
    BIGNUM_CUDA a;      // Curve parameter a
    BIGNUM_CUDA b;      // Curve parameter b
    BIGNUM_CUDA order;  // Order of the base point
} EC_GROUP_CUDA;

__device__ void bn_to_montgomery(BIGNUM_CUDA *r, const BIGNUM_CUDA *a, const BN_MONT_CTX_CUDA *mont, BIGNUM_CUDA *m);

__device__ int ossl_ec_GFp_simple_ladder_pre(const EC_GROUP_CUDA *group,
    EC_POINT_JACOBIAN *r,
    EC_POINT_JACOBIAN *s,
    const EC_POINT_JACOBIAN *p);

__device__ int ossl_ec_GFp_simple_ladder_post(
    const EC_GROUP_CUDA *group,
    EC_POINT_JACOBIAN *r,
    EC_POINT_JACOBIAN *s,
    const EC_POINT_JACOBIAN *p);

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

// Helper function to invert a point
__device__ int EC_POINT_invert(EC_POINT_CUDA *r, const EC_POINT_CUDA *p, const BIGNUM_CUDA *field) {
    bn_copy(&r->x, &p->x);
    bn_mod_sub(&r->y, field, &p->y, field); // Negate y coordinate
    return 1;
}

__device__ void bn_mod_sqr_montgomery(BIGNUM_CUDA *r, const BIGNUM_CUDA *a, BIGNUM_CUDA *n) {
    // Compute r = a^2 mod n using Montgomery multiplication
    bn_mod_mul_montgomery(r, a, a, n);
}

__device__ bool ossl_bn_mod_sqr_montgomery(
    BIGNUM_CUDA *r,           // OpenSSL: result
    const BIGNUM_CUDA *a,     // OpenSSL: input to square
    const BIGNUM_CUDA *n      // OpenSSL: modulus from group->field
) {
    bn_print_no_fuse("ossl_bn_mod_sqr_montgomery >> a: ", a);
    bn_print_no_fuse("ossl_bn_mod_sqr_montgomery >> n: ", n);
    // Call CUDA's bn_mod_sqr_montgomery with reordered parameters
    bn_mod_mul_montgomery(a, a, n, r);
    bn_print_no_fuse("ossl_bn_mod_sqr_montgomery << r: ", r);
    return true;  // Return true for success to match OpenSSL's behavior
}

__device__ void bn_mod_lshift1(BIGNUM_CUDA *r, const BIGNUM_CUDA *a, const BIGNUM_CUDA *n) {
    // Compute r = (a << 1) mod n
    BIGNUM_CUDA temp;
    init_zero(&temp);
    
    // Perform left shift
    bn_copy(&temp, a);
    left_shift(&temp, 1);
    
    // Compute modulo n
    bn_mod(r, &temp, n);
}



__device__ int ossl_ec_GFp_mont_field_inv(const BIGNUM_CUDA *a, BIGNUM_CUDA *result, const BIGNUM_CUDA *p) {    
    printf("++ ossl_ec_GFp_mont_field_inv ++\n");
    bn_print_no_fuse(">> a: ", a);
    bn_print_no_fuse(">> p: ", p);
    // Check for invalid input
    if (bn_is_zero(a)) {
        return 0; // Cannot invert zero
    }

    // We'll use Fermat's Little Theorem: a^(p-2) mod p
    // First compute p-2
    BIGNUM_CUDA e;
    init_zero(&e);
    BIGNUM_CUDA two;
    init_zero(&two);
    two.d[0] = 2;
    two.top = 1;
        
    if (!bn_sub(&e, p, &two)) { // e = p - 2
        return 0;
    }

    // Now need to compute a^e mod p
    // We'll do this using repeated squaring and multiplying
    BIGNUM_CUDA base; // Copy of input a
    init_zero(&base);
    bn_copy(&base, a);
    
    BIGNUM_CUDA temp;
    init_zero(&temp);
    init_one(result);  // Start with result = 1

    // Get the bit length of e
    int bit_len = bn_bit_length(&e);
    
    // Process each bit of the exponent from left to right (MSB to LSB)
    for (int i = bit_len - 1; i >= 0; i--) {
        // Square the result
        bn_mod_mul(result, result, result, p);
        
        // If current bit is 1, multiply by base
        if (BN_is_bit_set(&e, i)) {
            bn_mod_mul(result, result, &base, p);
        }
    }

    // Verify result is not zero
    if (bn_is_zero(result)) {
        return 0; // Inversion failed
    }

    return 1;
}

// TODO: Test this function
__device__ int bn_mod_lshift_quick(BIGNUM_CUDA *r, const BIGNUM_CUDA *a, int n, const BIGNUM_CUDA *m) {
    // Left shift 'a' by 'n' bits modulo 'm', assuming that 'a' is non-negative and less than 'm'

    // Copy 'a' to 'r' if they are not the same
    // if (r != a) {
    if (bn_cmp(r, a) != 0) {
        bn_copy(r, a);
    }

    while (n > 0) {
        int max_shift;

        // Calculate the number of bits in 'm' and 'r'
        int bits_m = bn_bit_length(m);
        int bits_r = bn_bit_length(r);

        // Calculate maximum shift without exceeding modulus bit length
        max_shift = bits_m - bits_r;

        if (max_shift < 0) {
            // Error: Input not reduced (r >= m)
            printf("Error: Input not reduced\n");
            return 0;
        }

        // Limit max_shift to the remaining bits to shift
        if (max_shift > n)
            max_shift = n;

        if (max_shift > 0) {
            // Shift 'r' left by max_shift bits
            left_shift(r, max_shift);
            n -= max_shift;
        } else {
            // Shift 'r' left by 1 bit
            if (!bn_lshift1(r, r)) {
                return 0;
            }
            n -= 1;
        }

        // Reduce modulo 'm' if necessary
        if (bn_cmp(r, m) >= 0) {
            if (!bn_sub(r, r, m)) {
                return 0;
            }
        }
    }
    // print result
    bn_print_no_fuse("<< [L] BN_mod_lshift_quick r: ", r);
    return 1;
}

__device__ int ossl_ec_GFp_mont_field_mul(
    const BIGNUM_CUDA *p,
    BIGNUM_CUDA *r, 
    const BIGNUM_CUDA *a, 
    const BIGNUM_CUDA *b
    ) {
    bn_mod_mul_montgomery(a, b, p, r);
    return 1;
}

__device__ int ec_point_ladder_step(
    const EC_GROUP_CUDA *group,
    EC_POINT_JACOBIAN *r, 
    EC_POINT_JACOBIAN *s,
    const EC_POINT_JACOBIAN *p
) {
    BIGNUM_CUDA t0, t1, t2, t3, t4, t5, t6;
    
    // Initialize all temporary variables
    init_zero(&t0);
    init_zero(&t1);
    init_zero(&t2);
    init_zero(&t3);
    init_zero(&t4);
    init_zero(&t5);
    init_zero(&t6);

    printf("\n## ladder_step ##\n");
    print_jacobian_point(">> r", r);
    print_jacobian_point(">> s", s);
    print_jacobian_point(">> p", p);

    // Follow OpenSSL's OR logic order
    int ret = (
        // Initial steps
        ossl_bn_mod_mul_montgomery(&t6, &r->X, &s->X, &group->field) &&
        ossl_bn_mod_mul_montgomery(&t0, &r->Z, &s->Z, &group->field) &&
        ossl_bn_mod_mul_montgomery(&t4, &r->X, &s->Z, &group->field) &&
        ossl_bn_mod_mul_montgomery(&t3, &r->Z, &s->X, &group->field) &&
        ossl_bn_mod_mul_montgomery(&t5, &group->a, &t0, &group->field) &&
        bn_mod_add_quick(&t5, &t6, &t5, &group->field) &&
        bn_mod_add_quick(&t6, &t3, &t4, &group->field) &&
        ossl_bn_mod_mul_montgomery(&t5, &t6, &t5, &group->field) &&
        ossl_bn_mod_sqr_montgomery(&t0, &t0, &group->field)&&
        bn_mod_lshift_quick(&t2, &group->b, 2, &group->field)&&
        ossl_bn_mod_mul_montgomery(&t0, &t2, &t0, &group->field)&&
        bn_mod_lshift1_quick(&t5, &t5, &group->field)&&
        bn_mod_sub_quick(&t3, &t4, &t3, &group->field)&&

        // s->Z coord output
        ossl_bn_mod_sqr_montgomery(&s->Z, &t3, &group->field) &&
        ossl_bn_mod_mul_montgomery(&t4, &s->Z, &p->X, &group->field) &&
        bn_mod_add_quick(&t0, &t0, &t5, &group->field) &&

        // s->X coord output
        bn_mod_sub_quick(&s->X, &t0, &t4, &group->field) &&
        ossl_bn_mod_sqr_montgomery(&t4, &r->X, &group->field) &&
        ossl_bn_mod_sqr_montgomery(&t5, &r->Z, &group->field) &&
        ossl_bn_mod_mul_montgomery(&t6, &t5, &group->a, &group->field) &&
        bn_mod_add_quick(&t1, &r->X, &r->Z, &group->field) && // ERR
        ossl_bn_mod_sqr_montgomery(&t1, &t1, &group->field) &&
        bn_mod_sub_quick(&t1, &t1, &t4, &group->field) &&
        bn_mod_sub_quick(&t1, &t1, &t5, &group->field) &&
        bn_mod_sub_quick(&t3, &t4, &t6, &group->field) &&
        ossl_bn_mod_sqr_montgomery(&t3, &t3, &group->field) &&
        ossl_bn_mod_mul_montgomery(&t0, &t5, &t1, &group->field) &&
        ossl_bn_mod_mul_montgomery(&t0, &t2, &t0, &group->field) &&

        // r->X coord output 
        bn_mod_sub_quick(&r->X, &t3, &t0, &group->field) &&
        bn_mod_add_quick(&t3, &t4, &t6, &group->field) &&
        ossl_bn_mod_sqr_montgomery(&t4, &t5, &group->field) &&
        ossl_bn_mod_mul_montgomery(&t4, &t4, &t2, &group->field) &&
        ossl_bn_mod_mul_montgomery(&t1, &t1, &t3, &group->field) &&
        bn_mod_lshift1_quick(&t1, &t1, &group->field) &&

        // r->Z coord output
        bn_mod_add_quick(&r->Z, &t4, &t1, &group->field)
    );
    print_jacobian_point("<< ladder_step << r", r);
    print_jacobian_point("<< ladder_step << s", s);
    return ret;
}

__device__ void init_jacobian_point(EC_POINT_JACOBIAN *point) {
    init_zero(&point->X);
    init_zero(&point->Y);
    init_zero(&point->Z);
    // point->Z.d[0] = 1;  // Set Z = 1 by default
    // point->Z.top = 1;
}

typedef struct {
    BIGNUM_CUDA p;       // Prime field modulus
    BIGNUM_CUDA a;       // Curve parameter 'a'
    BIGNUM_CUDA b;       // Curve parameter 'b'
    BIGNUM_CUDA Gx;      // x-coordinate of the base point G
    BIGNUM_CUDA Gy;      // y-coordinate of the base point G
    BIGNUM_CUDA n;       // Order of the base point G
    BIGNUM_CUDA h;       // Cofactor
} CurveParameters;

__device__ int bn_is_odd(const BIGNUM_CUDA *a) {
    if (a->top == 0) {
        return 0;  // Zero is even
    }
    return a->d[0] & 1;
}

__device__ void bn_and_word(const BIGNUM_CUDA *a, BN_ULONG w, BIGNUM_CUDA *result) {
    init_zero(result);

    if (a->top == 0) {
        return;
    }

    result->d[0] = a->d[0] & w;
    result->top = 1;
    result->neg = a->neg;
}

__device__ int bn_hex2bn(BIGNUM_CUDA *bn, const char *hex_str) {
    init_zero(bn);

    int hex_len = 0;
    while (hex_str[hex_len] != '\0') {
        hex_len++;
    }

    int byte_len = (hex_len + 1) / 2;
    int num_words = (byte_len + sizeof(BN_ULONG) - 1) / sizeof(BN_ULONG);

    if (num_words > MAX_BIGNUM_SIZE) {
        // Exceeds maximum size
        return 0;
    }

    int hex_index = 0;
    int word_index = 0;
    BN_ULONG current_word = 0;
    int bits_in_current_word = 0;

    // Start from the end of the hex string
    for (int i = hex_len - 1; i >= 0; i--) {
        char c = hex_str[i];
        int value = 0;

        if (c >= '0' && c <= '9') {
            value = c - '0';
        } else if (c >= 'A' && c <= 'F') {
            value = 10 + c - 'A';
        } else if (c >= 'a' && c <= 'f') {
            value = 10 + c - 'a';
        } else {
            // Invalid character
            return 0;
        }

        current_word |= ((BN_ULONG)value) << bits_in_current_word;
        bits_in_current_word += 4;

        if (bits_in_current_word >= BN_ULONG_NUM_BITS) {
            bn->d[word_index++] = current_word;
            current_word = 0;
            bits_in_current_word = 0;
        }
    }

    if (bits_in_current_word > 0) {
        bn->d[word_index++] = current_word;
    }

    bn->top = word_index;
    bn->neg = false;

    // Remove leading zeros
    while (bn->top > 1 && bn->d[bn->top - 1] == 0) {
        bn->top--;
    }

    return 1;  // Success
}

__device__ int compute_wNAF(const BIGNUM_CUDA *scalar, int w, signed char *wNAF) {
    BIGNUM_CUDA k;
    bn_copy(&k, scalar);

    int width = w;
    int bits = bn_bit_length(&k);
    int sign = 1;
    int index = 0;
    int mask = (1 << width) - 1;

    if (bn_is_zero(&k)) {
        wNAF[0] = 0;
        return 1;
    }

    if (k.neg) {
        sign = -1;
        k.neg = 0;  // Make k positive
    }

    while (!bn_is_zero(&k)) {
        if (bn_is_odd(&k)) {
            BIGNUM_CUDA remainder;
            init_zero(&remainder);

            bn_and_word(&k, mask, &remainder);

            int digit = remainder.d[0];
            if (digit & (1 << (width - 1))) {
                digit -= (1 << width);
            }

            wNAF[index++] = (signed char)(digit * sign);

            BIGNUM_CUDA temp;
            init_zero(&temp);
            bn_set_word(&temp, abs(digit));
            bn_sub(&k, &k, &temp);
        } else {
            wNAF[index++] = 0;
        }
        bn_rshift1(&k);
    }
    return index;  // Returns the length of wNAF representation
}

__device__ void point_double_cuda(
    const EC_POINT_CUDA *P,
    EC_POINT_CUDA *result,
    const CurveParameters *curve_params
) {
    // Implement point doubling in affine coordinates or Jacobian coordinates.
    // For better performance, use Jacobian coordinates.
    // Here is a simplified version using affine coordinates:

    if (point_is_at_infinity(P)) {
        set_point_at_infinity(result);
        return;
    }

    BIGNUM_CUDA lambda, numerator, denominator, temp;
    init_zero(&lambda);
    init_zero(&numerator);
    init_zero(&denominator);
    init_zero(&temp);

    // numerator = 3 * x^2 + a
    bn_mod_sqr(&temp, &P->x, &curve_params->p);
    bn_set_word(&numerator, 3);
    bn_mod_mul(&numerator, &numerator, &temp, &curve_params->p);
    bn_mod_add(&numerator, &numerator, &curve_params->a, &curve_params->p);

    // denominator = 2 * y
    bn_set_word(&denominator, 2);
    bn_mod_mul(&denominator, &denominator, &P->y, &curve_params->p);

    // lambda = numerator / denominator mod p
    bn_mod_inverse(&denominator, &denominator, &curve_params->p);
    bn_mod_mul(&lambda, &numerator, &denominator, &curve_params->p);

    // x_r = lambda^2 - 2 * x
    bn_mod_sqr(&temp, &lambda, &curve_params->p);
    bn_mod_sub(&temp, &temp, &P->x, &curve_params->p);
    bn_mod_sub(&result->x, &temp, &P->x, &curve_params->p);

    // y_r = lambda * (x - x_r) - y
    bn_mod_sub(&temp, &P->x, &result->x, &curve_params->p);
    bn_mod_mul(&temp, &lambda, &temp, &curve_params->p);
    bn_mod_sub(&result->y, &temp, &P->y, &curve_params->p);
}

__device__ void point_add_cuda(
    EC_POINT_CUDA *result,
    const EC_POINT_CUDA *P,
    const EC_POINT_CUDA *Q,
    const CurveParameters *curve_params
) {
    // Handle special cases
    if (point_is_at_infinity(P)) {
        bn_copy(&result->x, &Q->x);
        bn_copy(&result->y, &Q->y);
        return;
    }
    if (point_is_at_infinity(Q)) {
        bn_copy(&result->x, &P->x);
        bn_copy(&result->y, &P->y);
        return;
    }

    if (bn_cmp(&P->x, &Q->x) == 0) {
        if (bn_cmp(&P->y, &Q->y) != 0) {
            // P + (-P) = 0
            set_point_at_infinity(result);
            return;
        } else {
            // P + P = 2P
            point_double_cuda(P, result, curve_params);
            return;
        }
    }

    BIGNUM_CUDA lambda, numerator, denominator, temp;
    init_zero(&lambda);
    init_zero(&numerator);
    init_zero(&denominator);
    init_zero(&temp);

    // numerator = y_Q - y_P
    bn_mod_sub(&numerator, &Q->y, &P->y, &curve_params->p);

    // denominator = x_Q - x_P
    bn_mod_sub(&denominator, &Q->x, &P->x, &curve_params->p);

    // lambda = numerator / denominator mod p
    bn_mod_inverse(&denominator, &denominator, &curve_params->p);
    bn_mod_mul(&lambda, &numerator, &denominator, &curve_params->p);

    // x_r = lambda^2 - x_P - x_Q
    bn_mod_sqr(&temp, &lambda, &curve_params->p);
    bn_mod_sub(&temp, &temp, &P->x, &curve_params->p);
    bn_mod_sub(&result->x, &temp, &Q->x, &curve_params->p);

    // y_r = lambda * (x_P - x_r) - y_P
    bn_mod_sub(&temp, &P->x, &result->x, &curve_params->p);
    bn_mod_mul(&temp, &lambda, &temp, &curve_params->p);
    bn_mod_sub(&result->y, &temp, &P->y, &curve_params->p);
}

__device__ void precompute_multiples(
    const EC_POINT_CUDA *point,
    EC_POINT_CUDA *precomputed_points,
    const CurveParameters *curve_params
) {
    // precomputed_points[0] = point
    bn_copy(&precomputed_points[0].x, &point->x);
    bn_copy(&precomputed_points[0].y, &point->y);

    EC_POINT_CUDA twoP;
    point_double_cuda(point, &twoP, curve_params);

    for (int i = 1; i < NUM_PRECOMPUTED_POINTS; i++) {
        point_add_cuda(&precomputed_points[i], &precomputed_points[i - 1], &twoP, curve_params);
    }
}

__device__ void point_negate(
    const EC_POINT_CUDA *P,
    EC_POINT_CUDA *result,
    const CurveParameters *curve_params
) {
    bn_copy(&result->x, &P->x);
    bn_mod_sub(&result->y, &curve_params->p, &P->y, &curve_params->p);
}

__device__ void BN_consttime_swap(BN_ULONG condition, BIGNUM_CUDA *a, BIGNUM_CUDA *b) {
    BN_ULONG t;
    char max_top = max(a->top, b->top);
    
    condition = ((~condition & 1) - 1);

    // Swap words
    for (char i = 0; i < max_top; i++) {
        t = condition & (a->d[i] ^ b->d[i]);
        a->d[i] ^= t;
        b->d[i] ^= t;
    }

    // Swap top values
    char t_top = condition & (a->top ^ b->top);
    a->top ^= t_top;
    b->top ^= t_top;

    // Swap neg flags
    char t_neg = condition & (a->neg ^ b->neg);
    a->neg ^= t_neg;
    b->neg ^= t_neg;
}

__device__ void ossl_ec_scalar_mul_ladder(
    const EC_GROUP_CUDA *group,
    EC_POINT_JACOBIAN *r,
    const BIGNUM_CUDA *scalar,
    const EC_POINT_JACOBIAN *p)
{
    int cardinality_bits = 256;
    BIGNUM_CUDA k;
    init_zero(&k);
    EC_POINT_JACOBIAN s;
    init_zero(&s.X);
    init_zero(&s.Y);
    init_zero(&s.Z);

    bn_copy(&k, scalar); // Copy scalar to local variable k


    BIGNUM_CUDA lambda, cardinality;
    init_zero(&lambda);
    init_zero(&cardinality);
    
    bn_copy(&cardinality, &group->order);
    bn_print_no_fuse("## cardinality:", &cardinality);

    bn_add(&lambda, &k, &cardinality);
    bn_print_no_fuse("## lambda [2]:", &lambda);
    bn_print_no_fuse("# k [5]:", &k);
    
    bn_add(&k, &lambda, &cardinality);

    bn_print_no_fuse("# k [6]:", &k);

    int kbit = BN_is_bit_set(&lambda, cardinality_bits);
    printf("# kbit [0]: %d\n", kbit);
    BN_consttime_swap(kbit, &k, &lambda);
    printf("# kbit [1]: %d\n", kbit);

    bn_print_no_fuse("# k [7]:", &k);

    /* Initialize the Montgomery ladder */
    if (!ossl_ec_GFp_simple_ladder_pre(group, r, &s, p)) {
        printf("Ladder pre operation failed!\n");
        return;
    }
    printf("\nAfter ladder pre: (Before ladder step:)\n");
    print_jacobian_point("R", r);
    print_jacobian_point("S", &s);
    print_jacobian_point("P (base point)", p);

    /* top bit is a 1, in a fixed pos */
    int pbit = 1;

    #define EC_POINT_CSWAP(c, a, b) do {          \
        BN_consttime_swap(c, &(a)->X, &(b)->X);   \
        BN_consttime_swap(c, &(a)->Y, &(b)->Y);   \
        BN_consttime_swap(c, &(a)->Z, &(b)->Z);   \
    } while(0)

    // Add swapping logic - for testing use kbit=1 to ensure swap happens
    // int kbit = 1;  // This should come from scalar bit

    // Perform the Montgomery ladder
    bn_print_no_fuse("# k [8]:", &k);

    

    // EC_POINT_CSWAP(kbit, r, &s);

    for (int i = cardinality_bits - 1; i >= 0; i--) {
        // kbit = BN_is_bit_set(&k, i) ^ pbit;
        kbit = BN_is_bit_set(&k, i);
        printf("** kbt: %d\n", i, kbit);
        kbit = kbit ^ pbit;
        printf(">> i: %d, kbit: %d\n", i, kbit);
        EC_POINT_CSWAP(kbit, r, &s);

        // printf("\nAfter swap:\n");
        // print_jacobian_point("R", r);
        // print_jacobian_point("S", &s);
        // print_jacobian_point("P (base point)", p);

        /* Perform a single step of the Montgomery ladder */
        if (!ec_point_ladder_step(group, r, &s, p)) {
            printf("Ladder step operation failed!\n");
            return;
        }
        /*
         * pbit logic merges this cswap with that of the
         * next iteration
         */
        pbit ^= kbit;
        printf("<< i: %d, pbit: %d\n", i, pbit); // Debug print
    }
    /* one final cswap to move the right value into r */
    EC_POINT_CSWAP(kbit, r, &s);
    printf("\nAfter ladder loop:\n");
    print_jacobian_point("R", r);
    print_jacobian_point("S", &s);
    print_jacobian_point("P (base point)", p);

    /* Finalize ladder (and recover full point coordinates) */
    if (!ossl_ec_GFp_simple_ladder_post(group, r, &s, p)) {
        printf("Ladder post operation failed!\n");
        return;
    }
    printf("\nAfter ossl_ec_GFp_simple_ladder_post:\n");
    print_jacobian_point("R", r);
    print_jacobian_point("S", &s);
    print_jacobian_point("P (base point)", p);
}

__device__ void ec_point_scalar_mul_wnaf(
    EC_POINT_JACOBIAN *result,
    const EC_POINT_JACOBIAN *point,
    const BIGNUM_CUDA *scalar,
    const CurveParameters *curve_params
) {
    // Print inputs
    printf("++ ec_point_scalar_mul_wnaf ++\n");
    bn_print_no_fuse(">> scalar: ", scalar);
    bn_print_no_fuse(">> point.x: ", &point->X);
    bn_print_no_fuse(">> point.y: ", &point->Y);
    bn_print_no_fuse(">> point.z: ", &point->Z);
    bn_print_no_fuse(">> curve_params->p: ", &curve_params->p);
    bn_print_no_fuse(">> curve_params->a: ", &curve_params->a);
    bn_print_no_fuse(">> curve_params->b: ", &curve_params->b);
    bn_print_no_fuse(">> curve_params->Gx: ", &curve_params->Gx);
    bn_print_no_fuse(">> curve_params->Gy: ", &curve_params->Gy);
    bn_print_no_fuse(">> curve_params->n: ", &curve_params->n);
    bn_print_no_fuse(">> curve_params->h: ", &curve_params->h);
    
    EC_GROUP_CUDA group;
    // Initialize secp256k1 curve parameters
    init_zero(&group.field);
    group.field.d[3] = 0xFFFFFFFFFFFFFFFF;
    group.field.d[2] = 0xFFFFFFFFFFFFFFFF;
    group.field.d[1] = 0xFFFFFFFFFFFFFFFF;
    group.field.d[0] = 0xFFFFFFFEFFFFFC2F;
    group.field.top = 4;
    group.field.neg = false;

    // a = 0
    init_zero(&group.a);
    group.a.top = 1;
    group.a.neg = false;

    // b = 700001AB7
    init_zero(&group.b);
    group.b.d[0] = 0x700001AB7;
    group.b.top = 1;
    group.b.neg = false;

    // Initialize curve order
    init_zero(&group.order);
    group.order.d[3] = 0xFFFFFFFFFFFFFFFF;
    group.order.d[2] = 0xFFFFFFFFFFFFFFFE;
    group.order.d[1] = 0xBAAEDCE6AF48A03B;
    group.order.d[0] = 0xBFD25E8CD0364141;
    group.order.top = 4;
    group.order.neg = false;

    ossl_ec_scalar_mul_ladder(&group, result, scalar, point);

    printf("-- ec_point_scalar_mul_wnaf --\n");
}

// It was written for EC_POINT_CUDA types.
__device__ void ec_point_scalar_mul_wnaf_deprecated(
    EC_POINT_JACOBIAN *result,
    const EC_POINT_JACOBIAN *point,
    const BIGNUM_CUDA *scalar,
    const CurveParameters *curve_params
) {
    // Print inputs
    printf("++ ec_point_scalar_mul_wnaf ++\n");
    bn_print_no_fuse(">> scalar: ", scalar);
    bn_print_no_fuse(">> point.x: ", &point->X);
    bn_print_no_fuse(">> point.y: ", &point->Y);
    bn_print_no_fuse(">> point.z: ", &point->Z);
    bn_print_no_fuse(">> curve_params->p: ", &curve_params->p);
    bn_print_no_fuse(">> curve_params->a: ", &curve_params->a);
    bn_print_no_fuse(">> curve_params->b: ", &curve_params->b);
    bn_print_no_fuse(">> curve_params->Gx: ", &curve_params->Gx);
    bn_print_no_fuse(">> curve_params->Gy: ", &curve_params->Gy);
    bn_print_no_fuse(">> curve_params->n: ", &curve_params->n);
    bn_print_no_fuse(">> curve_params->h: ", &curve_params->h);
    
    // // Step 1: Convert scalar to wNAF
    // signed char wNAF[MAX_WNAF_LENGTH];
    // int wNAF_len = compute_wNAF(scalar, WINDOW_SIZE, wNAF);

    // // Step 2: Precompute point multiples
    // EC_POINT_CUDA precomputed[NUM_PRECOMPUTED_POINTS];
    // precompute_multiples(point, precomputed, curve_params);

    // // Step 3: Initialize result to point at infinity
    // set_point_at_infinity(result);

    // // Step 4: Main loop
    // for (int i = wNAF_len - 1; i >= 0; i--) {
    //     // Double the result point
    //     point_double_cuda(result, result, curve_params);

    //     if (wNAF[i] != 0) {
    //         if (wNAF[i] > 0) {
    //             int idx = (wNAF[i] - 1) / 2;
    //             point_add_cuda(result, result, &precomputed[idx], curve_params);
    //         } else {
    //             int idx = (-wNAF[i] - 1) / 2;
    //             EC_POINT_CUDA neg_point;
    //             point_negate(&precomputed[idx], &neg_point, curve_params);
    //             point_add_cuda(result, result, &neg_point, curve_params);
    //         }
    //     }
    // }
}

__device__ void init_curve_parameters(CurveParameters *curve_params) {
    // Initialize the curve parameters for secp256k1, for example
    // Set p, a, b, Gx, Gy, n, h

    // Example for p:
    bn_hex2bn(&curve_params->p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");

    // Similarly for other parameters

}

__device__ void ec_point_scalar_mul_montgomery(
    const EC_POINT_JACOBIAN *point,
    const BIGNUM_CUDA *scalar,
    MONT_CTX_CUDA *mont_ctx,
    EC_POINT_JACOBIAN *result
) {

    bool debug = true;
    if (debug) {
        printf("++ ec_point_scalar_mul_montgomery ++\n");
        bn_print_no_fuse(">> point.x: ", &point->X);
        bn_print_no_fuse(">> point.y: ", &point->Y);
        bn_print_no_fuse(">> point.z: ", &point->Z);
        bn_print_no_fuse(">> scalar: ", scalar);
        bn_print_no_fuse(">> mont_ctx->R: ", &mont_ctx->R);
        bn_print_no_fuse(">> mont_ctx->n: ", &mont_ctx->n);
        bn_print_no_fuse(">> mont_ctx->n_prime: ", &mont_ctx->n_prime);
    }

    // Initialize curve parameters
    CurveParameters curve_params;
    init_curve_parameters(&curve_params);

    // Convert curve parameters to Montgomery form if necessary
    // For this example, let's assume that curve_params are already in Montgomery form

    // Call the wNAF scalar multiplication function
    ec_point_scalar_mul_wnaf(result, point, scalar, &curve_params);

    if (debug) {
        bn_print_no_fuse("<< result.x: ", &result->X);
        bn_print_no_fuse("<< result.y: ", &result->Y);
        bn_print_no_fuse("<< result.z: ", &result->Z);
        printf("-- ec_point_scalar_mul_montgomery --\n");
    }
}

__device__ int cuda_ec_GFp_mont_field_encode(const EC_GROUP_CUDA *group, 
                                           BIGNUM_CUDA *r,
                                           const BIGNUM_CUDA *a) {
    BIGNUM_CUDA tmp;
    init_zero(&tmp);

    // bn_print_no_fuse(">> cuda_ec_GFp_mont_field_encode >> a: ", a);
    bn_to_montgomery_short(r, a);
    // bn_print_no_fuse("<< cuda_ec_GFp_mont_field_encode << r: ", r);
    return 1;
}

/* Helper function to generate random numbers of specified bit length */
// __device__ bool bn_rand_words(BIGNUM_CUDA *rnd, int bits, int top, int bottom) {
// __device__ bool bn_rand_words(BIGNUM_CUDA *rnd, int bits) {
__device__ bool bnrand(BIGNUM_CUDA *rnd) {
    // int top = -1;
    // int bottom = 0;
    int bits = 256;
    bn_print_no_fuse(">> bn_rand_words >> rnd: ", rnd);
    // printf(">> bn_rand_words >> bits: %d\n", bits);
    // printf(">> bn_rand_words >> top: %d\n", top);
    // printf(">> bn_rand_words >> bottom: %d\n", bottom);

    const int BUFFER_SIZE = 32;  // 256 bits = 32 bytes
    unsigned char buf[BUFFER_SIZE] = {0};

    int bit = (bits - 1) % 8;
    unsigned char mask = 0xff << (bit + 1);

    // Fill buffer with random bytes
    for (int i = 0; i < BUFFER_SIZE; i++) {
        unsigned int seed = clock64() + threadIdx.x;
        buf[i] = (unsigned char)(seed % 256);
    }

    // Set buf to deterministic values
    for (int i = 0; i < BUFFER_SIZE; i++) {
        buf[i] = 0x63; // Set all bytes to 0x63 for testing. TODO: disable this line
    }

    // print mask
    printf("# bnrand mask: %d\n",mask);
    buf[0] &= ~mask;
    // if (bottom) {
    //     buf[BUFFER_SIZE - 1] |= 1;
    // }
    // print buf
    // for (int i = 0; i < BUFFER_SIZE; i++) {
    //     printf("buf[%d] = %02x\n", i, buf[i]);
    // } 
    // print buf
    for (int i = 0; i < BUFFER_SIZE; i++) {
        printf("%02x ", buf[i]);
    }
    printf("\n");

    // Convert buf to BIGNUM_CUDA
    init_zero(rnd);
    int word_index = 0;
    int i = BUFFER_SIZE - 1;

    while (i >= 0) {
        BN_ULONG word = 0;
        int shift = 0;
        int j;
        for (j = 0; j < sizeof(BN_ULONG) && i >= 0; j++, i--) {
            word |= ((BN_ULONG)buf[i]) << shift;
            shift += 8;
        }
        rnd->d[word_index++] = word;
    }

    rnd->top = word_index;

    bn_print_no_fuse("<< bn_rand_words << rnd: ", rnd);
    return true;
}
// __device__ bool bn_rand_range_words(BIGNUM_CUDA *r, int bits) {
//     bn_print_no_fuse(">> bn_rand_range_words >> r: ", r);
//     // OpenSSL bnrand implementation
//     int bytes = (bits + 7) / 8;  /* Convert bits to bytes, rounding up */
//     int extra_bits = 8 - (bits % 8);  /* Bits in most significant byte */
//     unsigned char *temp_buffer = NULL;
    
//     /* Allocate temporary buffer with enough space for random bytes */
//     temp_buffer = (unsigned char*)malloc(bytes);
//     if (!temp_buffer) {
//         return false;
//     }

//     /* Fill with random bytes using cuRAND */
//     for (int i = 0; i < bytes; i++) {
//         /* Use thread index and clock for seeding - could be improved */
//         unsigned int seed = clock64() + threadIdx.x;
//         temp_buffer[i] = (unsigned char)(seed % 256);
//     }

//     /* Mask off extra bits in the most significant byte */
//     if (extra_bits < 8)
//         temp_buffer[0] &= ((1 << (8 - extra_bits)) - 1);

//     /* Convert the bytes to BIGNUM_CUDA format */
//     init_zero(r);
//     int word_offset = 0;
//     BN_ULONG current_word = 0;
//     int bits_in_word = 0;

//     for (int i = bytes - 1; i >= 0; i--) {
//         current_word |= ((BN_ULONG)temp_buffer[i] << bits_in_word);
//         bits_in_word += 8;

//         if (bits_in_word >= BN_ULONG_NUM_BITS || i == 0) {
//             r->d[word_offset++] = current_word;
//             current_word = 0;
//             bits_in_word = 0;
//         }
//     }

//     r->top = word_offset;
//     if (r->top == 0)
//         r->top = 1;  /* Ensure at least one word */

//     /* Clean up temporary buffer */
//     free(temp_buffer);
//     bn_print_no_fuse("<< bn_rand_range_words << r: ", r);
//     return true;
// }

// __device__ bool BN_priv_rand_range_ex(BIGNUM_CUDA *r) {
//     return bnrand_range(r);
// }

__device__ bool BN_priv_rand_range_ex(BIGNUM_CUDA *r, const BIGNUM_CUDA *range,
                                     unsigned int strength, void *ctx) {
    // OpenSSL bnrand_range implementation
    int n;
    int count = 100;

    if (r == NULL) {
        printf("Error: Null pointer passed as result\n");
        return false;
    }

    if (range->neg || bn_is_zero(range)) {
        printf("Error: Invalid range\n");
        return false;
    }

    n = bn_num_bits(range);     /* n > 0 */

    /* BN_is_bit_set(range, n - 1) always holds */

    /* Single word? */
    if (n == 1) {
        init_zero(r);
        return true;
    } 
    
    /* Is range a power of 2? Special handling for improved uniformity */
    if ((n & (n - 1)) == 0 && !BN_is_bit_set(range, n - 2) 
        && !BN_is_bit_set(range, n - 3)) {
        /*
         * Range = 100..._2, so 3*range (= 11..._2) is exactly one bit longer
         * than range
         */
        do {
            /* Generate random number with one extra bit */
            // if (!bn_rand_range_words(r, n + 1)) {
            if (!bnrand(r)) {
                return false;
            }

            /* 
             * If r < 3*range, use r mod range (which is either r, r - range, 
             * or r - 2*range). Since 3*range = 11..._2, each iteration 
             * succeeds with probability >= .75
             */
            if (bn_cmp(r, range) >= 0) {
                if (!bn_sub(r, r, range))
                    return false;
                if (bn_cmp(r, range) >= 0)
                    if (!bn_sub(r, r, range))
                        return false;
            }

            if (!--count) {
                printf("Error: Too many iterations in random generation\n");
                return false;
            }

        } while (bn_cmp(r, range) >= 0);
    } else {
        /* Standard case - keep generating until we get a value < range */
        do {
            // if (!bn_rand_range_words(r, n)) {
            if (!bnrand(r)) {
                return false;
            }

            if (!--count) {
                printf("Error: Too many iterations in random generation\n");
                return false;
            }
        } while (bn_cmp(r, range) >= 0);
    }

    r->neg = false;
    return true;
}

__device__ int ossl_ec_GFp_simple_ladder_pre(const EC_GROUP_CUDA *group,
                                           EC_POINT_JACOBIAN *r,
                                           EC_POINT_JACOBIAN *s,
                                           const EC_POINT_JACOBIAN *p) {
    BIGNUM_CUDA t1, t2, t3, t4, t5;
    init_zero(&t1);
    init_zero(&t2); 
    init_zero(&t3);
    init_zero(&t4);
    init_zero(&t5);

    // Check if point p is at infinity
    if (bn_is_zero(&p->Z)) {
        init_zero(&r->X);
        init_zero(&r->Y);
        init_zero(&r->Z);
        init_zero(&s->X);
        init_zero(&s->Y); 
        init_zero(&s->Z);
        return 0;
    }

    // typedef struct ec_group_st_cuda {
    //     BIGNUM_CUDA field;  // Prime field modulus p
    //     BIGNUM_CUDA a;      // Curve parameter a
    //     BIGNUM_CUDA b;      // Curve parameter b
    //     BIGNUM_CUDA order;  // Order of the base point
    // } EC_GROUP_CUDA;
    // print group
    bn_print_no_fuse(">> ossl_ec_GFp_simple_ladder_pre group->field = ", &group->field);
    bn_print_no_fuse(">> ossl_ec_GFp_simple_ladder_pre group->a = ", &group->a);
    bn_print_no_fuse(">> ossl_ec_GFp_simple_ladder_pre group->b = ", &group->b);
    bn_print_no_fuse(">> ossl_ec_GFp_simple_ladder_pre group->order = ", &group->order);
    bn_print_no_fuse(">> ossl_ec_GFp_simple_ladder_pre s->X = ", &s->X);
    bn_print_no_fuse(">> ossl_ec_GFp_simple_ladder_pre s->Y = ", &s->Y);
    bn_print_no_fuse(">> ossl_ec_GFp_simple_ladder_pre s->Z = ", &s->Z);
    bn_print_no_fuse(">> ossl_ec_GFp_simple_ladder_pre p->X = ", &p->X);
    bn_print_no_fuse(">> ossl_ec_GFp_simple_ladder_pre p->Y = ", &p->Y);
    bn_print_no_fuse(">> ossl_ec_GFp_simple_ladder_pre p->Z = ", &p->Z);
    printf("Debug: Computed:\n");

    if (!ossl_bn_mod_sqr_montgomery(&t3, &p->X, &group->field))
        return 0;
    bn_print_no_fuse("[0] t3 = X^2 = ", &t3);

    if (!bn_mod_sub_quick(&t4, &t3, &group->a, &group->field))
        return 0;
    bn_print_no_fuse("[1] t4 = t3 - a = ", &t4);

    if (!ossl_bn_mod_sqr_montgomery(&t4, &t3, &group->field))
        return 0;
    bn_print_no_fuse("[2] t4 = t4^2 = ", &t4);

    if (!ossl_bn_mod_mul_montgomery(&t5, &p->X, &group->b, &group->field))
        return 0;
    bn_print_no_fuse("[3] t5 = X * b = ", &t5);

    if (!bn_mod_lshift_quick(&t5, &t5, 3, &group->field))
        return 0;
    bn_print_no_fuse("[4] t5 = t5 << 3 = ", &t5); 

    bn_print_no_fuse(">> t4 = ", &t4);
    bn_print_no_fuse(">> t5 = ", &t5);
    bn_print_no_fuse(">> group->field = ", &group->field);
    if (!bn_mod_sub_quick(&r->X, &t4, &t5, &group->field))
        return 0;
    // bn_print_no_fuse("[5] r->X = (X^2 - a)^2 - X * b * 8 = ", &r->X); // ERR
    bn_print_no_fuse("[5] r->X = t4 - t5 = ", &r->X);

    bn_print_no_fuse(">> t3 = ", &t3);
    bn_print_no_fuse(">> group->a = ", &group->a);
    if (!bn_mod_add_quick(&t1, &t3, &group->a, &group->field))
        return 0;
    bn_print_no_fuse("[6] t1 = t3 + a = ", &t1);

    if (!ossl_bn_mod_mul_montgomery(&t2, &p->X, &t1, &group->field))
        return 0;
    bn_print_no_fuse("[7] t2 = X * t1 = ", &t2);

    if (!bn_mod_add_quick(&t2, &t2, &group->b, &group->field))
        return 0;
    bn_print_no_fuse("[8] t2 = b + t2 = ", &t2);

    if (!bn_mod_lshift_quick(&r->Z, &t2, 2, &group->field))    
        return 0;
    bn_print_no_fuse("[9] r->Z = t2 << 2 = ", &r->Z);

    // Set the corresponding values
    // t1 = s->Z;
    // t2 = r->Z;
    // t3 = s->X;
    // t4 = r->X;
    // t5 = s->Y;
    
    bn_copy(&s->Z, &t1);
    // bn_copy(&r->Z, &t2);
    bn_copy(&s->X, &t3);
    // bn_copy(&r->X, &t4);
    bn_copy(&s->Y, &t5);

    // bn_print_no_fuse("[pre-field_encode] s->Z = ", &s->Z);
    // bn_print_no_fuse("[pre-field_encode] r->Z = ", &r->Z);
    // bn_print_no_fuse("[pre-field_encode] s->X = ", &s->X);
    // bn_print_no_fuse("[pre-field_encode] r->X = ", &r->X);
    // bn_print_no_fuse("[pre-field_encode] s->Y = ", &s->Y);

    printf(">> ossl_ec_GFp_simple_ladder_pre.before_blinding >>\n");
    // r, s
    bn_print_no_fuse(">> r->X = ", &r->X);
    bn_print_no_fuse(">> r->Y = ", &r->Y);
    bn_print_no_fuse(">> r->Z = ", &r->Z);
    bn_print_no_fuse(">> s->X = ", &s->X);
    bn_print_no_fuse(">> s->Y = ", &s->Y);
    bn_print_no_fuse(">> s->Z = ", &s->Z);
    
    // Blinding ++
    // &r->Y becomes non-zero
    bool perform_blinding = true;
    if (perform_blinding) {
        /* make sure lambda (r->Y here for storage) is not zero */
        do {
            // Use a private range function to generate non-zero random value
            if (!BN_priv_rand_range_ex(&r->Y, &group->field, 0, NULL))
                return 0;
        } while (bn_is_zero(&r->Y));

        /* make sure lambda (s->Z here for storage) is not zero */
        do {
            if (!BN_priv_rand_range_ex(&s->Z, &group->field, 0, NULL))
                return 0;
        } while (bn_is_zero(&s->Z));
    }

    // /* if field_encode defined convert between representations */
    // if (group->meth->field_encode != NULL) {
    //     if (!cuda_ec_GFp_mont_field_encode(group, &r->Y, &r->Y) ||
    //         !cuda_ec_GFp_mont_field_encode(group, &s->Z, &s->Z))
    //         return 0;
    // }

    // /* Blind r and s independently */
    // if (!ossl_ec_GFp_mont_field_mul(&group->field, &r->Z, &r->Z, &r->Y) ||
    //     !ossl_ec_GFp_mont_field_mul(&group->field, &r->X, &r->X, &r->Y) ||
    //     !ossl_ec_GFp_mont_field_mul(&group->field, &s->X, &p->X, &s->Z))  /* s := p */
    //     return 0;
    // Blinding --

    /* if field_encode defined convert between representations */    
    // Encode r->Y
    cuda_ec_GFp_mont_field_encode(group, &r->Y, &r->Y);
    // Encode s->Z
    cuda_ec_GFp_mont_field_encode(group, &s->Z, &s->Z);

    // r->Z = r->Z * r->Y
    ossl_ec_GFp_mont_field_mul(&group->field, &r->Z, &r->Z, &r->Y);
    bn_print_no_fuse("[b] r->z = ", &r->Z);

    // r->X = r->X * r->Y
    ossl_ec_GFp_mont_field_mul(&group->field, &r->X, &r->X, &r->Y);
    bn_print_no_fuse("[b] r->X = ", &r->X);

    // s->X = p->X * s->Z
    ossl_ec_GFp_mont_field_mul(&group->field, &s->X, &p->X, &s->Z);
    bn_print_no_fuse("[b] s->X = ", &s->X);

    

    return 1;
}

__device__ int ossl_ec_GFp_simple_ladder_post(
    const EC_GROUP_CUDA *group,
    EC_POINT_JACOBIAN *r,
    EC_POINT_JACOBIAN *s,
    const EC_POINT_JACOBIAN *p
) {
    if (bn_is_zero(&r->Z)) {
        // Set r to point at infinity
        init_zero(&r->X);
        init_zero(&r->Y);
        init_zero(&r->Z);
        return 1;
    }

    if (bn_is_zero(&s->Z)) {
        // If s is infinity, r = -P
        bn_copy(&r->X, &p->X);
        // Negate Y coordinate: -Y = p - Y
        bn_mod_sub(&r->Y, &group->field, &p->Y, &group->field);
        init_one(&r->Z);
        return 1;
    }

    // Initialize temporary variables
    BIGNUM_CUDA t0, t1, t2, t3, t4, t5, t6;
    init_zero(&t0);
    init_zero(&t1);
    init_zero(&t2);
    init_zero(&t3);
    init_zero(&t4);
    init_zero(&t5);
    init_zero(&t6);

    // t4 = 2*Y1
    bn_mod_lshift1_quick(&t4, &p->Y, &group->field);

    // t6 = X2*t4*Z3*Z2
    ossl_bn_mod_mul_montgomery(&t6, &r->X, &t4, &group->field);
    ossl_bn_mod_mul_montgomery(&t6, &t6, &s->Z, &group->field);
    ossl_bn_mod_mul_montgomery(&t5, &r->Z, &t6, &group->field);

    // t1 = 2*b*Z3
    bn_mod_lshift1_quick(&t1, &group->b, &group->field);
    ossl_bn_mod_mul_montgomery(&t1, &t1, &s->Z, &group->field);

    // t3 = Z2^2
    ossl_bn_mod_sqr_montgomery(&t3, &r->Z, &group->field);

    // t2 = t3*t1
    ossl_bn_mod_mul_montgomery(&t2, &t3, &t1, &group->field);

    // t6 = Z2*a
    ossl_bn_mod_mul_montgomery(&t6, &r->Z, &group->a, &group->field);

    // t1 = X1*X2 + t6
    ossl_bn_mod_mul_montgomery(&t1, &p->X, &r->X, &group->field);
    bn_mod_add_quick(&t1, &t1, &t6, &group->field);

    // t1 = t1*Z3
    ossl_bn_mod_mul_montgomery(&t1, &t1, &s->Z, &group->field);

    // t0 = X1*Z2
    ossl_bn_mod_mul_montgomery(&t0, &p->X, &r->Z, &group->field);

    // t6 = X2 + t0
    bn_mod_add_quick(&t6, &r->X, &t0, &group->field);

    // t6 = t6*t1
    ossl_bn_mod_mul_montgomery(&t6, &t6, &t1, &group->field);

    // t6 = t6 + t2
    bn_mod_add_quick(&t6, &t6, &t2, &group->field);

    // t0 = t0 - X2
    bn_mod_sub_quick(&t0, &t0, &r->X, &group->field);

    // t0 = t0^2
    ossl_bn_mod_sqr_montgomery(&t0, &t0, &group->field);

    // t0 = t0*X3
    ossl_bn_mod_mul_montgomery(&t0, &t0, &s->X, &group->field);

    // t0 = t6 - t0
    bn_mod_sub_quick(&t0, &t6, &t0, &group->field);

    // t1 = Z3*t4
    ossl_bn_mod_mul_montgomery(&t1, &s->Z, &t4, &group->field);

    // t1 = t1*t3
    ossl_bn_mod_mul_montgomery(&t1, &t1, &t3, &group->field);

    // Compute final coordinates
    // if (!ossl_ec_GFp_mont_field_inv(group, t1, &t1, &group->field)) {
    if (!ossl_ec_GFp_mont_field_inv(&t1, &t1, &group->field)) {
        return 0;
    }

    // Compute X coordinate
    ossl_bn_mod_mul_montgomery(&r->X, &t5, &t1, &group->field);

    // Compute Y coordinate
    ossl_bn_mod_mul_montgomery(&r->Y, &t0, &t1, &group->field);

    // Set Z coordinate to 1
    init_one(&r->Z);

    return 1;
}