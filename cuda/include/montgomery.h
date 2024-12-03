#define TABLE_SIZE 32 // Maximum precomputation table size for sliding windows
#define N0_VALUE 0xd838091dd2253531ULL
#define BN_MASK2 0xFFFFFFFFFFFFFFFFULL


// Structure to store Montgomery context
typedef struct {
    BIGNUM_CUDA R;       // Montgomery radix (R = 2^k where k is the bit length of n)
    BIGNUM_CUDA n;       // The modulus
    BIGNUM_CUDA n_prime; // -n^(-1) mod R (also called N')
    BIGNUM_CUDA R2;      // R^2 mod n (used for Montgomery reduction)
} BN_MONT_CTX_CUDA;

__device__ bool BN_MONT_CTX_set(BN_MONT_CTX_CUDA *mont, const BIGNUM_CUDA *m);

__device__ void bn_rshift(BIGNUM_CUDA *r, const BIGNUM_CUDA *a, int shift) {
    if (shift == 0) {
        bn_copy(r, a);
        return;
    }
    int word_shift = shift / BN_ULONG_NUM_BITS;
    int bit_shift = shift % BN_ULONG_NUM_BITS;
    for (int i = 0; i < a->top - word_shift; i++) {
        BN_ULONG hi = a->d[i + word_shift];
        BN_ULONG lo = (i + word_shift + 1 < a->top) ? a->d[i + word_shift + 1] : 0;
        r->d[i] = (hi >> bit_shift) | (lo << (BN_ULONG_NUM_BITS - bit_shift));
    }
    r->top = a->top - word_shift;
    while (r->top > 0 && r->d[r->top - 1] == 0)
        r->top--;
}

__device__ void bn_mask_bits(BIGNUM_CUDA *r, int bits) {
    int word_index = bits / BN_ULONG_NUM_BITS;
    int bit_index = bits % BN_ULONG_NUM_BITS;
    if (word_index >= r->top)
        return;
    if (bit_index == 0) {
        r->top = word_index;
    } else {
        r->top = word_index + 1;
        BN_ULONG mask = (1UL << bit_index) - 1;
        r->d[word_index] &= mask;
    }
    while (r->top > 0 && r->d[r->top - 1] == 0)
        r->top--;
}

// Multiply a BIGNUM_CUDA by a BN_ULONG word
__device__ void bn_mul_word(BIGNUM_CUDA *r, const BIGNUM_CUDA *a, BN_ULONG w) {
    BN_ULONG carry = 0;
    for (int i = 0; i < a->top; i++) {
        unsigned __int128 prod = (unsigned __int128)a->d[i] * w + carry;
        r->d[i] = (BN_ULONG)prod;
        carry = (BN_ULONG)(prod >> 64);
    }
    r->d[a->top] = carry;
    r->top = a->top + (carry ? 1 : 0);
}

// Right shift a BIGNUM_CUDA by a number of words
__device__ void bn_rshift_words(BIGNUM_CUDA *r, const BIGNUM_CUDA *a, int words) {
    if (words >= a->top) {
        init_zero(r);
        return;
    }
    for (int i = 0; i < a->top - words; i++) {
        r->d[i] = a->d[i + words];
    }
    r->top = a->top - words;
}

__device__ BN_ULONG bn_mul_add_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w) {
    BN_ULONG carry = 0;
    for (int i = 0; i < num; i++) {
        unsigned __int128 mul = (unsigned __int128)ap[i] * w + rp[i] + carry;
        rp[i] = (BN_ULONG)mul;
        carry = (BN_ULONG)(mul >> BN_BITS2);
    }
    return carry;
}

__device__ BN_ULONG bn_sub_words(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b, int n) {
    BN_ULONG borrow = 0;
    for (int i = 0; i < n; i++) {
        BN_ULONG ai = a[i];
        BN_ULONG bi = b[i];
        BN_ULONG bi_borrow = bi + borrow;
        borrow = (bi_borrow < bi) ? 1 : 0; // Check for overflow in bi + borrow
        borrow += (ai < bi_borrow) ? 1 : 0;
        r[i] = ai - bi_borrow;
    }
    return borrow;
}

__device__ void bn_mod_mul_montgomery(
    const BIGNUM_CUDA *a, 
    const BIGNUM_CUDA *b,
    const BIGNUM_CUDA *n,
    BIGNUM_CUDA *ret
) {
    // bn_print_no_fuse("\nbn_mod_mul_montgomery >> a: ", a);
    // bn_print_no_fuse("bn_mod_mul_montgomery >> b: ", b);
    // bn_print_no_fuse("bn_mod_mul_montgomery >> n: ", n);
    // Multiply a and b
    BIGNUM_CUDA r;
    init_zero(&r);
    bn_mul(a, b, &r);
    
    int nl = n->top;
    int max = 2 * nl;

    // Ensure r has enough space
    BIGNUM_CUDA t;
    init_zero(&t);
    for (int i = 0; i < max; i++) {
        t.d[i] = (i < r.top) ? r.d[i] : 0;
    }
    t.top = max;
    
    // Montgomery reduction
    BN_ULONG n0 = N0_VALUE;
    BN_ULONG carry = 0;
    
    // Main Montgomery reduction loop
    for (int i = 0; i < nl; i++) {
        // Calculate m = (t[i] * n0) mod word_size
        BN_ULONG m = (t.d[i] * n0) & BN_MASK2;
        
        // Compute m*n and add to t
        BN_ULONG c = 0;
        for (int j = 0; j < nl; j++) {
            unsigned __int128 prod = (unsigned __int128)m * n->d[j] + t.d[i + j] + c;
            t.d[i + j] = (BN_ULONG)prod;
            c = (BN_ULONG)(prod >> 64);
        }
        
        // Add carries
        BN_ULONG v = t.d[i + nl] + c + carry;
        t.d[i + nl] = v;
        carry = (v < c) || ((v == c) && carry);
    }

    // Copy upper half to temporary variables and ensure proper initialization
    BIGNUM_CUDA tmp, tmp2;
    init_zero(&tmp);
    init_zero(&tmp2);
    
    // Copy the upper half properly, maintaining word count
    for (int i = 0; i < nl; i++) {
        tmp.d[i] = t.d[i + nl];
    }
    tmp.top = find_top_optimized(&tmp, nl);
    
    // Perform subtraction
    BN_ULONG borrow = bn_sub_words(tmp2.d, tmp.d, n->d, nl);
    tmp2.top = find_top_optimized(&tmp2, nl);
    
    // Initialize return value
    init_zero(ret);
    
    // Determine if subtraction is needed
    if (carry || bn_cmp(&tmp, n) >= 0) {
        // Use subtracted value, ensuring all words are copied
        for (int i = 0; i < nl; i++) {
            ret->d[i] = tmp2.d[i];
        }
    } else {
        // Use original value, ensuring all words are copied
        for (int i = 0; i < nl; i++) {
            ret->d[i] = tmp.d[i];
        }
    }
    
    // Ensure proper top value for result
    ret->top = find_top_optimized(ret, nl);
    // bn_print_no_fuse("bn_mod_mul_montgomery << r: ", ret);
}

__device__ bool ossl_bn_mod_mul_montgomery(
    BIGNUM_CUDA *result,           // OpenSSL: r
    const BIGNUM_CUDA *a,          // OpenSSL: a
    const BIGNUM_CUDA *b,          // OpenSSL: b
    const BIGNUM_CUDA *n           // OpenSSL: mont->N
    
) {
    bn_print_no_fuse("\nbn_mod_mul_montgomery >> a: ", a);
    bn_print_no_fuse("bn_mod_mul_montgomery >> b: ", b);
    // bn_print_no_fuse("bn_mod_mul_montgomery >> n: ", n);
    // Call CUDA's bn_mod_mul_montgomery with reordered parameters
    bn_mod_mul_montgomery(a, b, n, result);
    bn_print_no_fuse("bn_mod_mul_montgomery << r: ", result);
    return true;  // Since CUDA version returns void, we return true for success
}

__device__ void bn_to_montgomery(BIGNUM_CUDA *r, const BIGNUM_CUDA *a, const BN_MONT_CTX_CUDA *mont, BIGNUM_CUDA *m) {
    bn_mod_mul_montgomery(r, a, &mont->R2, m);
}

__device__ void bn_to_montgomery_short(BIGNUM_CUDA *r, const BIGNUM_CUDA *a) {
    BIGNUM_CUDA RR; // Pre-computed R^2 mod N value 
    init_zero(&RR);
    RR.d[1] = 0x1; // Upper 64 bits
    RR.d[0] = 0x7a2000e90a1; // Lower 64 bits  
    RR.top = 2;
    RR.neg = 0;

    BIGNUM_CUDA n; // Secp256k1 modulus
    init_zero(&n);
    n.d[3] = 0xFFFFFFFFFFFFFFFF;
    n.d[2] = 0xFFFFFFFFFFFFFFFF;
    n.d[1] = 0xFFFFFFFFFFFFFFFF;
    n.d[0] = 0xFFFFFFFEFFFFFC2F;
    n.top = 4;
    n.neg = 0;
    
    // Perform Montgomery multiplication: r = a * RR mod n
    bn_mod_mul_montgomery(a, &RR, &n, r);
}

// Helper function to expand BIGNUM_CUDA to a given word size
__device__ int bn_wexpand(BIGNUM_CUDA *bn, int words) {
    if (words <= MAX_BIGNUM_SIZE) {
        return 1;  // Already large enough
    }
    return 0;  // Cannot expand in this implementation
}

__device__ int bn_from_montgomery_word(BIGNUM_CUDA *ret, BIGNUM_CUDA *r, const BN_MONT_CTX_CUDA *mont) {
    bn_print_no_fuse("\n>> bn_from_montgomery_word >> ret:", ret);
    bn_print_no_fuse(">> bn_from_montgomery_word >> r:", r);
    bn_print_no_fuse(">> bn_from_montgomery_word >> mont->n:", &mont->n);
    bn_print_no_fuse(">> bn_from_montgomery_word >> mont->n_prime:", &mont->n_prime);

    // We need to modify 'r' directly as per the OpenSSL implementation.
    // Ensure that 'r' has enough space to hold the computations.

    BIGNUM_CUDA n;
    init_zero(&n);
    n = mont->n;
    int nl = n.top;

    if (nl == 0) {
        ret->top = 0;
        return 1;
    }

    int max = 2 * nl;

    // Ensure 'r' and 'ret' have enough space
    if (max > MAX_BIGNUM_SIZE) {
        printf("Error: required size exceeds MAX_BIGNUM_SIZE\n");
        return 0;
    }

    // Adjust 'r's sign
    r->neg ^= n.neg;

    BN_ULONG *np = n.d;
    BN_ULONG *rp = r->d;

    // Clear the top words of 'r'
    for (int i = r->top; i < max; i++) {
        rp[i] = 0;
    }

    r->top = max;

    // Use the precomputed n0 from the Montgomery context
    BN_ULONG n0 = mont->n_prime.d[0];  // Assuming mont->n_prime.d[0] holds the value of n0

    BN_ULONG carry = 0;

    // Main Montgomery reduction loop
    for (int i = 0; i < nl; i++) {
        // Compute m = (r->d[i] * n0) mod word_size
        BN_ULONG m = (rp[i] * n0) & BN_MASK2;

        // Compute m * n and add to r starting at position i
        BN_ULONG c = 0;
        for (int j = 0; j < nl; j++) {
            unsigned __int128 prod = (unsigned __int128)m * np[j] + rp[i + j] + c;
            rp[i + j] = (BN_ULONG)prod;
            c = (BN_ULONG)(prod >> BN_ULONG_NUM_BITS);
        }

        // Add carries
        unsigned __int128 sum = (unsigned __int128)rp[i + nl] + c + carry;
        rp[i + nl] = (BN_ULONG)sum;
        carry = (BN_ULONG)(sum >> BN_ULONG_NUM_BITS);
    }

    // Prepare 'ret' for the result
    ret->top = nl;
    ret->neg = r->neg;
    BN_ULONG *ap = &rp[nl];
    BN_ULONG *rp_ret = ret->d;

    // Perform subtraction: rp_ret = ap - np
    BN_ULONG borrow = bn_sub_words(rp_ret, ap, np, nl);

    // Adjust carry
    int carry_int = (int)carry - (int)borrow;  // carry and borrow are 0 or 1
    BN_ULONG mask = (BN_ULONG)(0) - (BN_ULONG)(carry_int & 1);  // All bits set if carry_int == -1

    // Conditional copy based on carry
    for (int i = 0; i < nl; i++) {
        rp_ret[i] = (mask & ap[i]) | (~mask & rp_ret[i]);
        ap[i] = 0;  // Clear the used words
    }

    // Correct the top of 'ret'
    ret->top = find_top_optimized(ret, nl);

    bn_print_no_fuse("\nbn_from_montgomery_word << ret:", ret);
    printf("\n");

    return 1;
}


__device__ int bn_from_mont_fixed_top(BIGNUM_CUDA *ret, const BIGNUM_CUDA *a, const BN_MONT_CTX_CUDA *mont) {
    BIGNUM_CUDA t;
    init_zero(&t);
    bn_copy(&t, a);
    return bn_from_montgomery_word(ret, &t, mont);
}

__device__ int BN_from_montgomery(BIGNUM_CUDA *ret, const BIGNUM_CUDA *a, const BN_MONT_CTX_CUDA *mont) {
    int retn;

    // First do the fixed top conversion
    retn = bn_from_mont_fixed_top(ret, a, mont);

    // Correct the top by removing leading zeros
    if (retn) {
        while (ret->top > 0 && ret->d[ret->top - 1] == 0)
            ret->top--;
    }

    // Handle zero case 
    if (ret->top == 0) {
        ret->neg = 0;  // Zero is always positive
    }

    return retn;
}

// int ossl_ec_GFp_mont_field_decode(const EC_GROUP_CUDA *group, BIGNUM_CUDA *r,
//                                   const BIGNUM_CUDA *a, BN_MONT_CTX_CUDA *ctx)
// {
//     // if (group->field_data1 == NULL) {
//     //     ERR_raise(ERR_LIB_EC, EC_R_NOT_INITIALIZED);
//     //     return 0;
//     // }

//     return BN_from_montgomery(r, a, group->field_data1, ctx);
// }

// __device__ void BN_from_montgomery_CUDA_prototype(BIGNUM_CUDA *r, const BIGNUM_CUDA *a, const BN_MONT_CTX_CUDA *mont) {
//     // Montgomery reduction: computes r = a * R^{-1} mod n
//     BIGNUM_CUDA t;
//     init_zero(&t);
//     bn_copy(&t, a);

//     // m = (t * mont->n_prime) mod mont->R
//     BIGNUM_CUDA m;
//     init_zero(&m);
//     bn_mod_mul(&m, &t, &mont->n_prime, &mont->R);

//     // u = (t + m * mont->n) / mont->R
//     BIGNUM_CUDA mn_product;
//     init_zero(&mn_product);
//     bn_mul(&m, &mont->n, &mn_product);  // m * n

//     BIGNUM_CUDA t_plus_mn;
//     init_zero(&t_plus_mn);
//     bn_add(&t_plus_mn, &t, &mn_product);  // t + m*n

//     BIGNUM_CUDA u;
//     init_zero(&u);
//     bn_div(&u, NULL, &t_plus_mn, &mont->R); // u = (t + m * n) / R

//     // If u >= n, subtract n
//     if (bn_cmp(&u, &mont->n) >= 0) {
//         bn_sub(&u, &u, &mont->n);
//     }

//     bn_copy(r, &u);
// }

__device__ int ossl_ec_GFp_mont_field_decode(const EC_GROUP_CUDA *group, BIGNUM_CUDA *r,
                                  const BIGNUM_CUDA *a)
{
    init_zero(r);
    // print group
    bn_print_no_fuse("ossl_ec_GFp_mont_field_decode >> group->field:", &group->field);
    bn_print_no_fuse("ossl_ec_GFp_mont_field_decode >> r:", r);
    bn_print_no_fuse("ossl_ec_GFp_mont_field_decode >> a:", a);

    // if (field == NULL) {
    //     ERR_raise(ERR_LIB_EC, EC_R_NOT_INITIALIZED);
    //     return 0;
    // }

    // return BN_from_montgomery(r, a, group->field_data1, ctx);
    // BN_from_montgomery_CUDA_prototype(r, a, field);

    BIGNUM_CUDA n;
    init_zero(&n);
    bn_copy(&n, &group->field);

    // Create Montgomery context
    BN_MONT_CTX_CUDA mont; // Memory optimization is possible using BIGNUM instead of mont
    BN_MONT_CTX_set(&mont, &n);

    BIGNUM_CUDA n_prime;
    init_zero(&n_prime);
    n_prime.d[0] = 0xd838091dd2253531;
    n_prime.top = 1;
    n_prime.neg = 0;

    // Set n_prime in montgomery context
    mont.n_prime = n_prime;

    return BN_from_montgomery(r, a, &mont);
}

// Function to count the number of bits in a BN_ULONG
__device__ int bn_num_bits_word(BN_ULONG l) {
    if (l == 0)
        return 0;
    // Use the intrinsic function __clzll to count leading zeros
    return BN_BITS2 - __clzll(l);
}

__device__ int bn_num_bits(const BIGNUM_CUDA *a) {
    if (a == NULL || a->top == 0)
        return 0;

    // Start with bits from all full words except the highest one
    int bits = (a->top - 1) * BN_BITS2;

    // Get the highest word
    BN_ULONG l = a->d[a->top - 1];

    // Add the number of bits in the highest word
    bits += bn_num_bits_word(l);

    return bits;
}

// Initialize Montgomery context
__device__ bool BN_MONT_CTX_set(BN_MONT_CTX_CUDA *mont, const BIGNUM_CUDA *m) {
    bool debug = true;

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

// Montgomery exponentiation
__device__ int BN_mod_exp_mont(BIGNUM_CUDA *r, const BIGNUM_CUDA *a, const BIGNUM_CUDA *p, BIGNUM_CUDA *m) {
    bool debug = true;

    if (debug) {
        printf("++ BN_mod_exp_mont ++\n");
        bn_print_no_fuse(">> BN_mod_exp_mont >> r =", r);
        bn_print_no_fuse(">> BN_mod_exp_mont >> a =", a);
        bn_print_no_fuse(">> BN_mod_exp_mont >> p =", p);
        bn_print_no_fuse(">> BN_mod_exp_mont >> m =", m);
    }    

    BN_MONT_CTX_CUDA mont;
    // Initialize Montgomery context
    if (!BN_MONT_CTX_set(&mont, m)) {
        printf("BN_MONT_CTX_set failed\n");
        return 0;
    }
    // if (debug) {
    //     printf("mont: \n");
    //     bn_print_no_fuse("  R: ", &mont.R);
    //     bn_print_no_fuse("  n: ", &mont.n);
    //     bn_print_no_fuse("  n_prime: ", &mont.n_prime);
    //     bn_print_no_fuse("  R2: ", &mont.R2);
    // }
    int i, bits, ret = 0, wstart, wend, window;
    int start = 1;
    /* Table of variables obtained from 'ctx' */
    BIGNUM_CUDA val[TABLE_SIZE];

    bits = bn_num_bits(p);
    printf(">> BN_mod_exp_mont >> bits = %d\n", bits);
    if (bits == 0) {
        // ret = BN_one(r); // init_one instead
        init_one(r);
        ret = 1;
        if (debug) printf("-- [0] BN_mod_exp_mont --\n");
        return ret;
    }

    BIGNUM_CUDA aa, rr, d;
    init_zero(&aa);
    init_zero(&rr);
    init_zero(&d);
    init_zero(&val[0]);

    if (a->neg || bn_cmp_abs(a, m) >= 0) {
        bn_mod(&aa, a, m);
    } else {
        bn_copy(&aa, a);
    }

    // 1
    bn_print_no_fuse("# BN_mod_exp_mont [1] >> val[0]: ", &val[0]);
    bn_print_no_fuse("# BN_mod_exp_mont [1] >> aa: ", &aa);
    bn_print_no_fuse("# BN_mod_exp_mont [1] >> mont.R2: ", &mont.R2);
    bn_print_no_fuse("# BN_mod_exp_mont [1] >> m: ", m);
    // bn_mod_mul_montgomery(&val[0], &aa, &mont.R2, m);
    ossl_bn_mod_mul_montgomery(&val[0], &aa, &mont.R2, m);
    bn_print_no_fuse("# BN_mod_exp_mont [1] << val[0]: ", &val[0]);

    window = BN_window_bits_for_exponent_size(bits);
    int j = 0;
    if (window > 1) {
        // 2
        bn_print_no_fuse("# BN_mod_exp_mont [2] >> d: ", &d);
        bn_print_no_fuse("# BN_mod_exp_mont [2] >> val[0]: ", &val[0]);
        ossl_bn_mod_mul_montgomery(&d, &val[0], &val[0], m);
        bn_print_no_fuse("# BN_mod_exp_mont [2] << d: ", &d);
        j = 1 << (window - 1);
        for (i = 1; i < j; i++) {
            init_zero(&val[i]);
            ossl_bn_mod_mul_montgomery(&val[i], &val[i - 1], &d, m);
        }
    }
    if (debug) printf("BN_mod_exp_mont: precompute done\n");
    bn_print_no_fuse("BN_mod_exp_mont [2.post_loop] >> d: ", &d);
    for (i = 1; i < j; i++) {
        printf("BN_mod_exp_mont [2.post_loop] >> val[%d]: ", i);
        bn_print_no_fuse("", &val[i]);
    }
    // Tests passed until here

    start = 1;                  
    wstart = bits - 1;          
    wend = 0;   

    // Initialize rr by converting 1 to Montgomery form
    BIGNUM_CUDA one;
    init_one(&one);
    bn_print_no_fuse("BN_mod_exp_mont [2.a] >> rr:", &rr);
    bn_print_no_fuse("BN_mod_exp_mont [2.a] >> one:", &one);
    bn_print_no_fuse("BN_mod_exp_mont [2.a] >> mont.R2:", &mont.R2);
    bn_print_no_fuse("BN_mod_exp_mont [2.a] >> m:", m);
    // bn_to_montgomery(&rr, &one, &mont, m);
    ossl_bn_mod_mul_montgomery(&rr, &one, &mont.R2, m);
    bn_print_no_fuse("BN_mod_exp_mont [2.a] << rr:", &rr);
    int debug_counter = -1;
    for (;;) {
        debug_counter++;
        int wvalue;

        if (BN_is_bit_set(p, wstart) == 0) {
            if (!start) {
                printf("BN_mod_exp_mont >> [2.b.%d]  >> rr:", debug_counter);
                bn_print_no_fuse("", &rr);
                ossl_bn_mod_mul_montgomery(&rr, &rr, &rr, m);
                printf("BN_mod_exp_montr >> [2.b.%d]  << rr:", debug_counter);
                bn_print_no_fuse("", &rr);
            }
            if (wstart == 0)
                break;
            wstart--;
            continue;
        }
        
        wvalue = 1;
        wend = 0;
        for (i = 1; i < window; i++) {
            if (wstart - i < 0)
                break;
            if (BN_is_bit_set(p, wstart - i)) {
                wvalue <<= (i - wend);
                wvalue |= 1;
                wend = i;
            }
        }
        printf("BN_mod_exp_mont >> [2.c.%d] >> rr: ", debug_counter);
        bn_print_no_fuse("", &rr); // WRONG
        int j = wend + 1;
        if (!start) {
            for (i = 0; i < j; i++) {
                printf("BN_mod_exp_mont >> [2.d.%d.%d] >> rr:", debug_counter, i);
                bn_print_no_fuse("", &rr);
                ossl_bn_mod_mul_montgomery(&rr, &rr, &rr, m);
                printf("BN_mod_exp_mont >> [2.d.%d.%d] << rr:", debug_counter, i);
                bn_print_no_fuse("", &rr);
            }
        }
        printf("BN_mod_exp_mont >> [2.e.%d.%d] << rr:", debug_counter, i);
        bn_print_no_fuse("", &rr);

        ossl_bn_mod_mul_montgomery(&rr, &rr, &val[wvalue >> 1], m);

        wstart -= wend + 1;
        start = 0;
        if (wstart < 0)
            break;
    }

    // Montgomery reduction
    // BIGNUM_CUDA one;
    init_one(&one);
    ossl_bn_mod_mul_montgomery(r, &rr, &one, m);
    ret = 1;
    if (debug) {
        bn_print_no_fuse("<< r: ", r);
        printf("-- BN_mod_exp_mont --\n");
    }
    return ret;
}