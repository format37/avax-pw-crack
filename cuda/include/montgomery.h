// #include "bignum.h"
// #include "point.h"

#define TABLE_SIZE 32 // Maximum precomputation table size for sliding windows
#define N0_VALUE 0xd838091dd2253531ULL
// #define BN_MASK2        (BN_MASK >> BN_BITS4) // Lower half bits set
#define BN_MASK2 0xFFFFFFFFFFFFFFFFULL


// Structure to store Montgomery context
typedef struct {
    BIGNUM_CUDA R;       // Montgomery radix (R = 2^k where k is the bit length of n)
    BIGNUM_CUDA n;       // The modulus
    BIGNUM_CUDA n_prime; // -n^(-1) mod R (also called N')
    BIGNUM_CUDA R2;      // R^2 mod n (used for Montgomery reduction)
} BN_MONT_CTX_CUDA;

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

__device__ BN_ULONG compute_n0(const BIGNUM_CUDA *n) {
    BN_ULONG n_mod = n->d[0]; // n mod 2^64
    BN_ULONG n0 = 1;

    // Newton-Raphson iteration to compute inverse modulo 2^64
    for (int i = 0; i < 6; i++) {
        n0 = n0 * (2 - n_mod * n0);
    }

    // Negate n0 to get -n^{-1} mod 2^64
    n0 = (BN_ULONG)(0 - n0);

    return n0;
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
        unsigned __int128 mul = (unsigned __int128)ap[i] * w;
        mul += carry;
        mul += rp[i];
        rp[i] = (BN_ULONG)mul;
        carry = (BN_ULONG)(mul >> 64);
    }
    return carry;
}

__device__ BN_ULONG bn_sub_words(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b, int n) {
    BN_ULONG borrow = 0;
    for (int i = 0; i < n; i++) {
        BN_ULONG temp = a[i] - b[i] - borrow;
        borrow = (a[i] < b[i] + borrow) || (borrow && a[i] == b[i]);
        r[i] = temp;
    }
    return borrow;
}

__device__ void bn_mod_mul_montgomery(
    const BIGNUM_CUDA *a, 
    const BIGNUM_CUDA *b,
    const BIGNUM_CUDA *n,
    BIGNUM_CUDA *ret
) {
    // First do standard multiplication
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
    
    for (int i = 0; i < nl; i++) {
        BN_ULONG v;
        // Calculate m = (r[i] * n0) mod word_size
        BN_ULONG m = (t.d[i] * n0) & BN_MASK2;
        // r[i:i+nl] += m * n
        v = bn_mul_add_words(&t.d[i], n->d, nl, m);
        v = (v + carry + t.d[i + nl]) & BN_MASK2;
        carry |= (v != t.d[i + nl]);
        carry &= (v <= t.d[i + nl]);
        t.d[i + nl] = v;
    }

    // Ensure ret has enough space
    init_zero(ret);
    
    // Final subtraction
    BIGNUM_CUDA tmp;
    init_zero(&tmp);
    
    // Copy higher words
    for (int i = 0; i < nl; i++) {
        tmp.d[i] = t.d[i + nl];
    }
    tmp.top = nl;
    
    // Subtract if necessary
    if (carry || bn_cmp(&tmp, n) >= 0) {
        bn_sub(&tmp, &tmp, n);
    }    
    bn_copy(ret, &tmp);
    // Find top - can start search from n->top since result < n
    ret->top = find_top_optimized(ret, n->top);    
}

__device__ void bn_mod_mul_montgomery_deprecated(
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
    printf("++ bn_mod_mul_montgomery ++\n");
    bn_print_no_fuse(">> a: ", a);
    bn_print_no_fuse(">> b: ", b);
    bn_print_no_fuse(">> n: ", n);
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
    // bn_mod_mul(&m, &t, &n_prime, &R);
    bn_mul(&t, &n_prime, &m);
    bn_mask_bits(&m, k);  // k is the bit length of R

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
    // init_zero(&u);
    // init_zero(&tmp);
    // // bn_div(quotient, remainder, dividend, divisor)
    // bn_div(&u, &tmp, &t_plus_mn, &R); // (t + m*n) / R

    // Compute u = (t + m * n) / R
    bn_mul(&m, n, &mn_product);
    bn_add(&t_plus_mn, &t, &mn_product);
    bn_rshift(&u, &t_plus_mn, k);

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
    bn_print_no_fuse("u (final result): ", &u);
    // Copy u to result
    // BIGNUM_CUDA tmp_result;
    // init_zero(&tmp_result);
    // bn_copy(&tmp_result, &u);

    bn_copy(result_of_multiplication, &u);
    ;
}

__device__ bool ossl_bn_mod_mul_montgomery(
    BIGNUM_CUDA *result,           // OpenSSL: r
    const BIGNUM_CUDA *a,          // OpenSSL: a
    const BIGNUM_CUDA *b,          // OpenSSL: b
    const BIGNUM_CUDA *n           // OpenSSL: mont->N
    
) {
    bn_print_no_fuse("\nbn_mod_mul_montgomery >> a: ", a);
    bn_print_no_fuse("bn_mod_mul_montgomery >> b: ", b);
    bn_print_no_fuse("bn_mod_mul_montgomery >> n: ", n);
    // Call CUDA's bn_mod_mul_montgomery with reordered parameters
    bn_mod_mul_montgomery(a, b, n, result);
    bn_print_no_fuse("bn_mod_mul_montgomery << result: ", result);
    return true;  // Since CUDA version returns void, we return true for success
}

__device__ void bn_mod_mul_montgomery_proto(BIGNUM_CUDA *r, const BIGNUM_CUDA *a, const BIGNUM_CUDA *b, const BIGNUM_CUDA *m, const BN_MONT_CTX_CUDA *mont) {
    bool debug = false;

    if (debug) {
        printf("++ bn_mod_mul_montgomery ++\n");
        bn_print_no_fuse("r: ", r);
        bn_print_no_fuse("a: ", a);
        bn_print_no_fuse("b: ", b);
        bn_print_no_fuse("m: ", m);
        printf("mont:\n");
        bn_print_no_fuse("  R: ", &mont->R);
        bn_print_no_fuse("  n: ", &mont->n);
        bn_print_no_fuse("  n_prime: ", &mont->n_prime);
        bn_print_no_fuse("  R2: ", &mont->R2);
    }
    BIGNUM_CUDA t, u, product;
    init_zero(&t);
    init_zero(&u);
    init_zero(&product);


    // 1. t = a * b
    bn_mul(a, b, &t);
    if (debug) bn_print_no_fuse("1. t = a * b: ", &t); // OK

    // 2. u = (t * n_prime) % R
    bn_mul(&t, &mont->n_prime, &u);
    if (debug) bn_print_no_fuse("2. u = (t * n_prime): ", &u); // OK
    BIGNUM_CUDA remainder_u;
    init_zero(&remainder_u);
    bn_div(&product, &remainder_u, &u, &mont->R);
    if (debug) bn_print_no_fuse("2. remainder_u: ", &remainder_u);
    bn_copy(&u, &remainder_u);
    
    if (debug) bn_print_no_fuse("2. u = (t * n_prime) % R: ", &u);

    // 3. product = (t + u * m) / R
    bn_mul(&u, m, &product);
    if (debug) bn_print_no_fuse("3. product = u * m: ", &product);
    init_zero(&u); // reuse u variable to store t + product value
    bn_add(&u, &t, &product);
    if (debug) bn_print_no_fuse("3. u = t + product: ", &u); // OK
    init_zero(&product); // reuse variable to store quotient
    BIGNUM_CUDA remainder;
    init_zero(&remainder);    
    bn_div(&product, &remainder, &u, &mont->R);
    if (debug) bn_print_no_fuse("3. product = (t + u * m) / R: ", &product);

    // 4. if product >= m: product -= m;
    if (bn_cmp(&product, m) >= 0) {
        bn_sub(&t, &product, m);
        bn_copy(&product, &t);
    }
    if (debug) bn_print_no_fuse("4. product = (t + u * m) / R (after sub): ", &product);
    bn_copy(r, &product);

    if (debug) {
        bn_print_no_fuse("<< r: ", r);
        printf("-- bn_mod_mul_montgomery --\n");
    }
}

__device__ void bn_to_montgomery(BIGNUM_CUDA *r, const BIGNUM_CUDA *a, const BN_MONT_CTX_CUDA *mont, const BIGNUM_CUDA *m) {
    bn_mod_mul_montgomery_proto(r, a, &mont->R2, m, mont);
}

__device__ void BN_from_montgomery_CUDA(BIGNUM_CUDA *r, const BIGNUM_CUDA *a, BN_MONT_CTX_CUDA *mont) {
    // Montgomery reduction: computes r = a * R^{-1} mod n
    BIGNUM_CUDA t;
    init_zero(&t);
    bn_copy(&t, a);

    // m = (t * mont->n_prime) mod mont->R
    BIGNUM_CUDA m;
    init_zero(&m);
    bn_mod_mul(&m, &t, &mont->n_prime, &mont->R);

    // u = (t + m * mont->n) / mont->R
    BIGNUM_CUDA mn_product;
    init_zero(&mn_product);
    bn_mul(&m, &mont->n, &mn_product);  // m * n

    BIGNUM_CUDA t_plus_mn;
    init_zero(&t_plus_mn);
    bn_add(&t_plus_mn, &t, &mn_product);  // t + m*n

    BIGNUM_CUDA u;
    init_zero(&u);
    bn_div(&u, NULL, &t_plus_mn, &mont->R); // u = (t + m * n) / R

    // If u >= n, subtract n
    if (bn_cmp(&u, &mont->n) >= 0) {
        bn_sub(&u, &u, &mont->n);
    }

    bn_copy(r, &u);
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

// Montgomery exponentiation
__device__ int BN_mod_exp_mont(BIGNUM_CUDA *r, const BIGNUM_CUDA *a, const BIGNUM_CUDA *p, const BIGNUM_CUDA *m) {
    bool debug = true;

    if (debug) {
        printf("++ BN_mod_exp_mont ++\n");
        bn_print_no_fuse(">> r: ", r);
        bn_print_no_fuse(">> a: ", a);
        bn_print_no_fuse(">> p: ", p);
        bn_print_no_fuse(">> m: ", m);
    }    

    BN_MONT_CTX_CUDA mont;
    // Initialize Montgomery context
    if (!BN_MONT_CTX_set(&mont, m)) {
        printf("BN_MONT_CTX_set failed\n");
        return 0;
    }
    if (debug) {
        printf("mont: \n");
        bn_print_no_fuse("  R: ", &mont.R);
        bn_print_no_fuse("  n: ", &mont.n);
        bn_print_no_fuse("  n_prime: ", &mont.n_prime);
        bn_print_no_fuse("  R2: ", &mont.R2);
    }
    int i, bits, ret = 0, wstart, wend, window;
    int start = 1;
    /* Table of variables obtained from 'ctx' */
    BIGNUM_CUDA val[TABLE_SIZE];

    bits = bn_num_bits(p);

    if (bits == 0) {
        // ret = BN_one(r); // init_one instead
        init_one(r);
        ret = 1;
        if (debug) printf("-- BN_mod_exp_mont --\n");
        return ret;
    }

    BIGNUM_CUDA aa, rr, d;
    init_zero(&aa);
    init_zero(&rr);
    init_zero(&d);
    init_zero(&val[0]);


    // if (a->neg || BN_ucmp(a, m) >= 0) {
    // use bn_cmp_abs instead
    if (a->neg || bn_cmp_abs(a, m) >= 0) {
        bn_mod(&aa, a, m);
    } else {
        bn_copy(&aa, a);
    }

    // 1
    bn_mod_mul_montgomery_proto(&val[0], &aa, &mont.R2, m, &mont);

    window = BN_window_bits_for_exponent_size(bits);
    if (window > 1) {
        // 2
        bn_mod_mul_montgomery_proto(&d, &val[0], &val[0], m, &mont);
        int j = 1 << (window - 1);
        for (i = 1; i < j; i++) {
            init_zero(&val[i]);
            bn_mod_mul_montgomery_proto(&val[i], &val[i - 1], &d, m, &mont);
        }
    }
    if (debug) printf("BN_mod_exp_mont: precompute done\n");


    start = 1;                  
    wstart = bits - 1;          
    wend = 0;   

    // init_one(&rr);
    // Initialize rr by converting 1 to Montgomery form instead of using init_one
    BIGNUM_CUDA one;
    init_one(&one);
    bn_to_montgomery(&rr, &one, &mont, m);


    for (;;) {
        int wvalue;

        if (BN_is_bit_set(p, wstart) == 0) {
            if (!start) {
                bn_mod_mul_montgomery_proto(&rr, &rr, &rr, m, &mont);
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

        int j = wend + 1;
        if (!start) {
            for (i = 0; i < j; i++) {
                bn_mod_mul_montgomery_proto(&rr, &rr, &rr, m, &mont);
            }
        }

        bn_mod_mul_montgomery_proto(&rr, &rr, &val[wvalue >> 1], m, &mont);

        wstart -= wend + 1;
        start = 0;
        if (wstart < 0)
            break;
    }

    // Montgomery reduction
    // BIGNUM_CUDA one;
    init_one(&one);
    bn_mod_mul_montgomery_proto(r, &rr, &one, m, &mont);
    ret = 1;
    if (debug) {
        bn_print_no_fuse("<< r: ", r);
        printf("-- BN_mod_exp_mont --\n");
    }
    return ret;
}