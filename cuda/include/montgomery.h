// #include "bignum.h"
// #include "point.h"

#define TABLE_SIZE 32 // Maximum precomputation table size for sliding windows

// Structure to store Montgomery context
typedef struct {
    BIGNUM_CUDA R;       // Montgomery radix (R = 2^k where k is the bit length of n)
    BIGNUM_CUDA n;       // The modulus
    BIGNUM_CUDA n_prime; // -n^(-1) mod R (also called N')
    BIGNUM_CUDA R2;      // R^2 mod n (used for Montgomery reduction)
} BN_MONT_CTX_CUDA;


__device__ void bn_mod_neg(BIGNUM_CUDA *result, const BIGNUM_CUDA *n, const BIGNUM_CUDA *R) {
    // Compute -n mod R
    if (bn_cmp(n, R) < 0) {
        // If n < R, just subtract n from R
        bn_sub(result, R, n);
    } else {
        // If n >= R, first reduce n modulo R
        BIGNUM_CUDA tmp;
        init_zero(&tmp);
        bn_mod(&tmp, n, R);  // tmp = n mod R
        bn_sub(result, R, &tmp);  // result = R - (n mod R)
    }
}

__device__ bool compute_mont_nprime(BIGNUM_CUDA *n_prime, const BIGNUM_CUDA *n, const BIGNUM_CUDA *R) {
    bool debug = false;
    if (debug) {
        printf("++ compute_mont_nprime ++\n");
        bn_print_no_fuse(">> n: ", n);
        bn_print_no_fuse(">> R: ", R);
    }

    // Check for null pointers and invalid inputs
    if (bn_is_zero(n)) {
        printf("Error: modulus n cannot be zero\n");
        return false;
    }

    if (bn_is_zero(R)) {
        printf("Error: R cannot be zero\n");
        return false;
    }
    
    // Compute -n
    BIGNUM_CUDA neg_n;
    init_zero(&neg_n);
    bn_mod_neg(&neg_n, n, R);
    if (debug) bn_print_no_fuse("neg_n: ", &neg_n);

    // Compute (-n)^(-1) mod R using bn_mod_inverse
    return bn_mod_inverse(n_prime, &neg_n, R);
    
    // Result is already reduced modulo R since bn_mod_inverse handles this
    // No need for additional modulo operation
}

// Helper function to verify if two numbers are coprime
__device__ bool are_coprime(const BIGNUM_CUDA *a, const BIGNUM_CUDA *b) {
    BIGNUM_CUDA gcd;
    init_zero(&gcd);
    
    // Calculate GCD using extended Euclidean algorithm
    bn_extended_gcd(a, b, NULL, NULL, &gcd);
    
    // Numbers are coprime if their GCD is 1
    return bn_is_one(&gcd);
}

__device__ void bn_mod_mul_montgomery(
    const BIGNUM_CUDA *a, 
    const BIGNUM_CUDA *b, 
    const BIGNUM_CUDA *n, 
    BIGNUM_CUDA * __restrict__ result_of_multiplication
    ) {
    bool debug = false;
    if (debug) {
        printf("++ bn_mod_mul_montgomery ++\n");
        bn_print_no_fuse(">> a: ", a);
        bn_print_no_fuse(">> b: ", b);
        bn_print_no_fuse(">> n: ", n);
    }
    // BIGNUM_CUDA debug_bignum;
    // init_zero(&debug_bignum);
    // bn_copy(result_of_multiplication, &debug_bignum); // TODO: remove this line OK
    
    // Check for null inputs
    if (bn_is_zero(n)) {
        printf("Error: modulus n cannot be zero\n");
        init_zero(result_of_multiplication);
        return;
    }
    // Step 1: Calculate R = 2^k where k is the number of bits in n
    if (debug) printf("R calculation:\n");
    int k = bn_bit_length(n);
    if (debug) printf("k: %d\n", k);
    if (k == 0) {
        printf("Error: invalid modulus bit length\n");
        init_zero(result_of_multiplication);
        return;
    }
    
    BIGNUM_CUDA R;
    init_zero(&R);
    bn_set_word(&R, 1);
    left_shift(&R, k);
    if (debug) bn_print_no_fuse("R: ", &R);

    // Ensure R and n are coprime
    if (!are_coprime(&R, n)) {
        printf("Error: R and n must be coprime\n");
        return;
    }

    // Step 2: Compute n' = -n^{-1} mod R
    BIGNUM_CUDA n_prime;
    init_zero(&n_prime);
    if (!compute_mont_nprime(&n_prime, n, &R)) {
        printf("Error: Could not compute n_prime\n");
        return;
    }
    if (debug) bn_print_no_fuse("n_prime: ", &n_prime);

    // Step 3: Convert operands to Montgomery form using bn_mod_mul
    BIGNUM_CUDA a_bar, b_bar;
    init_zero(&a_bar);
    init_zero(&b_bar);
    // Calculate a_bar = (a * R) % n
    bn_mod_mul(&a_bar, a, &R, n);
    // Calculate b_bar = (b * R) % n
    bn_mod_mul(&b_bar, b, &R, n);
    // Debug prints
    if (debug) {
        printf("\nMontgomery form (RR values):\n");
        bn_print_no_fuse("aRR: ", &a_bar);
        bn_print_no_fuse("bRR: ", &b_bar);
    }

    // BIGNUM_CUDA debug_bignum;
    // init_zero(&debug_bignum);
    // bn_copy(result_of_multiplication, &debug_bignum); // TODO: remove this line OK

    // Step 4: Montgomery multiplication in Montgomery form
    BIGNUM_CUDA t;
    init_zero(&t);
    
    if (debug) printf("Montgomery multiplication steps:\n");
    // Calculate t = a_bar * b_bar
    bn_mul(&a_bar, &b_bar, &t);
    if (debug) bn_print_no_fuse("t = aRR * bRR: ", &t);
    BIGNUM_CUDA m;
    init_zero(&m);

    // BIGNUM_CUDA debug_bignum;
    // init_zero(&debug_bignum);
    // bn_copy(result_of_multiplication, &debug_bignum); // TODO: remove this line OK
    
    // Calculate m = (t * n_prime) % R
    bn_mod_mul(&m, &t, &n_prime, &R);

    // BIGNUM_CUDA debug_bignum;
    // init_zero(&debug_bignum);
    // bn_copy(result_of_multiplication, &debug_bignum); // TODO: remove this line ERR

    if (debug) bn_print_no_fuse("m = (t * n') mod R: ", &m);

    // BIGNUM_CUDA debug_bignum;
    // init_zero(&debug_bignum);
    // bn_copy(result_of_multiplication, &debug_bignum); // TODO: remove this line ERR
    
    // Calculate u = (t + m * n) // R
    BIGNUM_CUDA mn_product;
    init_zero(&mn_product);
    bn_mul(&m, n, &mn_product);  // m * n

    BIGNUM_CUDA t_plus_mn;
    init_zero(&t_plus_mn);
    bn_add(&t_plus_mn, &t, &mn_product);  // t + m*n

    // Divide by R (equivalent to right shift by k bits)
    BIGNUM_CUDA u, tmp;
    init_zero(&u);
    init_zero(&tmp);
    // bn_div(quotient, remainder, dividend, divisor)
    bn_div(&u, &tmp, &t_plus_mn, &R); // (t + m*n) / R

    // Final reduction step: if u ≥ n, subtract n
    if (bn_cmp(&u, n) >= 0) {
        BIGNUM_CUDA tmp;
        init_zero(&tmp);
        bn_sub(&tmp, &u, n);
        bn_copy(&u, &tmp);
    }
    if (debug) bn_print_no_fuse("u (first reduction): ", &u);

    // BIGNUM_CUDA debug_bignum;
    // init_zero(&debug_bignum);
    // bn_copy(result_of_multiplication, &debug_bignum); // TODO: remove this line ERR

    // Step 5: Convert result back from Montgomery form
    if (debug) printf("Conversion from Montgomery form:\n");
    init_zero(&t);
    // Copy u to t
    bn_copy(&t, &u);
    if (debug) bn_print_no_fuse("t: ", &t);
    // m = (t * n_prime) % R
    bn_mod_mul(&m, &t, &n_prime, &R);
    if (debug) bn_print_no_fuse("m = (t * n') mod R: ", &m);

    // u = (t + m * n) // R
    bn_mul(&m, n, &mn_product);  // m * n
    bn_add(&t_plus_mn, &t, &mn_product);  // t + m*n
    bn_div(&u, &tmp, &t_plus_mn, &R); // (t + m*n) / R

    // if u >= n: u -= n
    if (bn_cmp(&u, n) >= 0) {
        BIGNUM_CUDA tmp;
        init_zero(&tmp);
        bn_sub(&tmp, &u, n);
        bn_copy(&u, &tmp);
    }    
    if (debug) bn_print_no_fuse("u (final result): ", &u);
    // Copy u to result
    // BIGNUM_CUDA tmp_result;
    // init_zero(&tmp_result);
    // bn_copy(&tmp_result, &u);

    bn_copy(result_of_multiplication, &u);
    ;
}

// Basic window size calculation
__device__ int BN_window_bits_for_exponent_size(int bits) {
    if (bits > 671) return 6;
    if (bits > 239) return 5;
    if (bits > 79)  return 4;
    if (bits > 23)  return 3;
    return 1;
}

// Check if a bit is set
__device__ bool BN_is_bit_set(const BIGNUM_CUDA *a, int n) {
    if (n < 0) return 0;
    int word_index = n / BN_ULONG_NUM_BITS;
    int bit_index = n % BN_ULONG_NUM_BITS;
    
    if (word_index >= a->top) return 0;
    return (a->d[word_index] & ((BN_ULONG)1 << bit_index)) != 0;
}

// Initialize Montgomery context
__device__ bool BN_MONT_CTX_set(BN_MONT_CTX_CUDA *mont, const BIGNUM_CUDA *m) {
    bool debug = false;

    if (debug) {
        printf("++ BN_MONT_CTX_set ++\n");
        printf("mont: \n");
        bn_print_no_fuse("  R: ", &mont->R);
        bn_print_no_fuse("  n: ", &mont->n);
        bn_print_no_fuse("  n_prime: ", &mont->n_prime);
        bn_print_no_fuse("  R2: ", &mont->R2);
        bn_print_no_fuse("m: ", m);
    }
    int num_bits = bn_num_bits(m);

    if (num_bits == 0) {
        printf("Error: invalid modulus bit length\n");
        return false;
    }

    init_zero(&mont->R);
    init_zero(&mont->n);
    init_zero(&mont->n_prime);
    init_zero(&mont->R2);


    bn_copy(&mont->n, m); // Set modulus

    // Calculate R
    BIGNUM_CUDA R;
    init_zero(&R);
    bn_set_word(&R, 1);
    left_shift(&R, num_bits);
    bn_copy(&mont->R, &R);
    if (debug) bn_print_no_fuse("mont->R: ", &mont->R);


    // Calculate R2 mod m
    // init_zero(&mont->R2);
    // BIGNUM_CUDA tmp1, tmp2;
    // init_zero(&tmp1);
    // init_zero(&tmp2);
    // bn_copy(&tmp1, &R); // dest << src
    // bn_mul(&R, &tmp1, &tmp2); // a * b = tmp2
    // bn_mod(&mont->R2, &tmp2, m); // R^2 mod n

    bn_mod_sqr(&mont->R2, &R, m);  // Calculate R^2 mod m and store in mont->R2

    if (debug) bn_print_no_fuse("mont->R2: ", &mont->R2);

    // Calculate n' = -n^(-1) mod R
    if (!compute_mont_nprime(&mont->n_prime, m, &mont->R)) {
        printf("Error: Could not compute n_prime\n");
        return false;
    }
    if (debug) bn_print_no_fuse("mont->n_prime: ", &mont->n_prime);
    

    // Print results
    if (debug) {
        printf("mont: \n");
        bn_print_no_fuse("  R: ", &mont->R);
        bn_print_no_fuse("  n: ", &mont->n);
        bn_print_no_fuse("  n_prime: ", &mont->n_prime);
        bn_print_no_fuse("  R2: ", &mont->R2);
        printf("-- BN_MONT_CTX_set --\n");
    }
    return true;
}

// // Montgomery exponentiation
// __device__ int BN_mod_exp_mont(BIGNUM_CUDA *r, const BIGNUM_CUDA *a, const BIGNUM_CUDA *p, const BIGNUM_CUDA *m) {
//     bool debug = true;

//     if (debug) {
//         printf("++ BN_mod_exp_mont ++\n");
//         bn_print_no_fuse(">> r: ", r);
//         bn_print_no_fuse(">> a: ", a);
//         bn_print_no_fuse(">> p: ", p);
//         bn_print_no_fuse(">> m: ", m);
//     }    

//     BN_MONT_CTX_CUDA mont;
//     // Initialize Montgomery context
//     if (!BN_MONT_CTX_set(&mont, m)) {
//         printf("BN_MONT_CTX_set failed\n");
//         return 0;
//     }
//     if (debug) {
//         printf("mont: \n");
//         bn_print_no_fuse("  R: ", &mont.R);
//         bn_print_no_fuse("  n: ", &mont.n);
//         bn_print_no_fuse("  n_prime: ", &mont.n_prime);
//         bn_print_no_fuse("  R2: ", &mont.R2);
//     }
//     int i, bits, ret = 0, wstart, wend, window;
//     int start = 1;
//     /* Table of variables obtained from 'ctx' */
//     BIGNUM_CUDA val[TABLE_SIZE];

//     bits = bn_num_bits(p);

//     if (bits == 0) {
//         // ret = BN_one(r); // init_one instead
//         init_one(r);
//         ret = 1;
//         if (debug) printf("-- BN_mod_exp_mont --\n");
//         return ret;
//     }

//     BIGNUM_CUDA aa, rr, d;
//     init_zero(&aa);
//     init_zero(&rr);
//     init_zero(&d);
//     init_zero(&val[0]);


//     // if (a->neg || BN_ucmp(a, m) >= 0) {
//     // use bn_cmp_abs instead
//     if (a->neg || bn_cmp_abs(a, m) >= 0) {
//         bn_mod(&aa, a, m);
//     } else {
//         bn_copy(&aa, a);
//     }

//     // 1
//     bn_mod_mul_montgomery(&val[0], &aa, &mont.R2, m, &mont);

//     window = BN_window_bits_for_exponent_size(bits);
//     if (window > 1) {
//         // 2
//         bn_mod_mul_montgomery(&d, &val[0], &val[0], m, &mont);
//         int j = 1 << (window - 1);
//         for (i = 1; i < j; i++) {
//             init_zero(&val[i]);
//             bn_mod_mul_montgomery(&val[i], &val[i - 1], &d, m, &mont);
//         }
//     }
//     if (debug) printf("BN_mod_exp_mont: precompute done\n");


//     start = 1;                  
//     wstart = bits - 1;          
//     wend = 0;   

//     init_one(&rr);

//     for (;;) {
//         int wvalue;

//         if (BN_is_bit_set(p, wstart) == 0) {
//             if (!start) {
//                 bn_mod_mul_montgomery(&rr, &rr, &rr, m, &mont);
//             }
//             if (wstart == 0)
//                 break;
//             wstart--;
//             continue;
//         }
        
//         wvalue = 1;
//         wend = 0;
//         for (i = 1; i < window; i++) {
//             if (wstart - i < 0)
//                 break;
//             if (BN_is_bit_set(p, wstart - i)) {
//                 wvalue <<= (i - wend);
//                 wvalue |= 1;
//                 wend = i;
//             }
//         }

//         int j = wend + 1;
//         if (!start) {
//             for (i = 0; i < j; i++) {
//                 bn_mod_mul_montgomery(&rr, &rr, &rr, m, &mont);
//             }
//         }

//         bn_mod_mul_montgomery(&rr, &rr, &val[wvalue >> 1], m, &mont);

//         wstart -= wend + 1;
//         start = 0;
//         if (wstart < 0)
//             break;
//     }

//     // Montgomery reduction
//     BIGNUM_CUDA one;
//     init_one(&one);
//     bn_mod_mul_montgomery(r, &rr, &one, m, &mont);
//     ret = 1;
//     if (debug) {
//         bn_print_no_fuse("<< r: ", r);
//         printf("-- BN_mod_exp_mont --\n");
//     }
//     return ret;
// }