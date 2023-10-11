#include "bn.h"

#define BN_MASK2 0xffffffff
#define BN_FLG_FIXED_TOP 0
#define BN_BITS4 32
#define BN_MASK2l (0xffffffffL)
#define BN_MASK2h (0xffffffff00000000L)
#define LBITS(a) ((a)&BN_MASK2l)
#define HBITS(a) (((a)>>BN_BITS4)&BN_MASK2l)
#define L2HBITS(a) (((a)<<BN_BITS4)&BN_MASK2)
#define bn_pollute(a)

#define mul64(l,h,bl,bh) \
        { \
        BN_ULONG m,m1,lt,ht; \
        lt=l; \
        ht=h; \
        m =(bh)*(lt); \
        lt=(bl)*(lt); \
        m1=(bl)*(ht); \
        ht =(bh)*(ht); \
        m=(m+m1)&BN_MASK2; ht += L2HBITS((BN_ULONG)(m < m1)); \
        ht+=HBITS(m); \
        m1=L2HBITS(m); \
        lt=(lt+m1)&BN_MASK2; ht += (lt < m1); \
        (l)=lt; \
        (h)=ht; \
        }

#define mul(r,a,bl,bh,c) \
        { \
        BN_ULONG l,h; \
        h= (a); \
        l=LBITS(h); \
        h=HBITS(h); \
        mul64(l,h,(bl),(bh)); \
        l+=(c); h += ((l&BN_MASK2) < (c)); \
        (c)=h&BN_MASK2; \
        (r)=l&BN_MASK2; \
        }

typedef struct bignum_st {
  BN_ULONG *d;
  int top;
  int dmax;
  int neg;
  int flags;
} BIGNUM;

__device__ void bn_print(char* msg, BIGNUM* a) {
  printf("%s", msg);
  for(int i=0; i<a->top; i++) {
    printf("%02x", a->d[i]);
    //printf("%s", BN_bn2hex(a));
  }
  printf("\n");
}

__device__ void init_zero(BIGNUM* r, int len) {
  for (int i = 0; i < len; i++) {
    r->d[i] = 0;
  }
  r->top = len;
  r->neg = 0;
}

__device__ void bn_add(BIGNUM* a, BIGNUM* b, BIGNUM* r) {
    int max = a->top > b->top ? a->top : b->top;
    BN_ULONG carry = 0;
    //printf("Starting addition... max: %d\n", max);

    for(int i=max-1; i>=0; i--) {
        BN_ULONG ai = (i < a->top) ? a->d[i] : 0;
        BN_ULONG bi = (i < b->top) ? b->d[i] : 0;

        BN_ULONG sum = ai + bi + carry;
        r->d[i] = sum;
        carry = (a->d[i] + bi + carry) > 0xFFFFFFFF ? 1 : 0;


        // Debug prints
        /*printf("i: %d", i);
        printf(", a->d[i]: %08x", ai);    
        printf(", b->d[i]: %08x", bi);
        printf(", sum: %08x", sum);
        printf(", result: %08x", r->d[i]);
        printf(", carry: %08x\n", carry);*/
    }

    // If there's a carry after processing all words
    if (carry) {
        r->top = max + 1;
        for (int i = r->top-1; i > 0; i--) {
            r->d[i] = r->d[i-1];
        }
        r->d[0] = carry;
    } else {
        r->top = max;
    }

    //printf("Finished addition.\n");
    // print r
    /*printf("r: ");
    for (int i = 0; i < r->top; i++) {
        printf("%08x\n", r->d[i]);
    }*/
}

__device__ int BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx)
{
    /*
     * like BN_mod, but returns non-negative remainder (i.e., 0 <= r < |d|
     * always holds)
     */

    if (!(BN_mod(r, m, d, ctx)))
        return 0;
    if (!r->neg)
        return 1;
    /* now   -|d| < r < 0,  so we have to set  r := r + |d| */
    return (d->neg ? BN_sub : BN_add) (r, r, d);
}

__device__ int bn_check_top_by_alex(const BIGNUM *a)
{
    BN_ULONG *A;
    int i;

    if (a->top > 0 && a->d[a->top - 1] == 0)
        return 0;
    A = a->d;
    for (i = 0; i < a->top; i++)
        if (A[i])
            return 1;
    return 0;
}

int bn_check_top_by_alex_v1(const BIGNUM *a)
{
    if (a->top < 0 || a->top > a->dmax) {
        abort();
    }
    return a->top;
}

__device__ static int bn_left_align(BIGNUM *num)
{
    BN_ULONG *d = num->d, n, m, rmask;
    int top = num->top;
    int rshift = BN_num_bits_word(d[top - 1]), lshift, i;

    lshift = BN_BITS2 - rshift;
    rshift %= BN_BITS2;            /* say no to undefined behaviour */
    rmask = (BN_ULONG)0 - rshift;  /* rmask = 0 - (rshift != 0) */
    rmask |= rmask >> 8;

    for (i = 0, m = 0; i < top; i++) {
        n = d[i];
        d[i] = ((n << lshift) | m) & BN_MASK2;
        m = (n >> rshift) & rmask;
    }

    return lshift;
}

/*__device__ int bn_wexpand_by_alex(BIGNUM *a, int words)
{
    BN_ULONG *new_d, *a_d;
    int i;

    if (a->dmax >= words)
        return 1;

    if ((new_d = OPENSSL_malloc(sizeof(BN_ULONG) * words)) == NULL)
        return 0;

    a_d = a->d;
    for (i = 0; i < a->top; i++)
        new_d[i] = a_d[i];
    for (; i < words; i++)
        new_d[i] = 0;

    OPENSSL_free(a->d);
    a->d = new_d;
    a->dmax = words;

    return 1;
}*/

/* This is used by bn_expand2() */
/* The caller MUST check that words > b->dmax before calling this */
__device__ static BN_ULONG *bn_expand_internal(const BIGNUM *b, int words)
{
    BN_ULONG *a = NULL;

    if (words > (INT_MAX / (4 * BN_BITS2))) {
        // ERR_raise(ERR_LIB_BN, BN_R_BIGNUM_TOO_LONG);
        printf("bn_expand_internal: BN_R_BIGNUM_TOO_LONG\n");
        return NULL;
    }
    if (BN_get_flags(b, BN_FLG_STATIC_DATA)) {
        // ERR_raise(ERR_LIB_BN, BN_R_EXPAND_ON_STATIC_BIGNUM_DATA);
        printf("bn_expand_internal: BN_R_EXPAND_ON_STATIC_BIGNUM_DATA\n");
        return NULL;
    }
    if (BN_get_flags(b, BN_FLG_SECURE))
        a = OPENSSL_secure_zalloc(words * sizeof(*a));
    else
        a = OPENSSL_zalloc(words * sizeof(*a));
    if (a == NULL)
        return NULL;

    assert(b->top <= words);
    if (b->top > 0)
        memcpy(a, b->d, sizeof(*a) * b->top);

    return a;
}

__device__ static void bn_free_d(BIGNUM *a, int clear)
{
    if (BN_get_flags(a, BN_FLG_SECURE))
        OPENSSL_secure_clear_free(a->d, a->dmax * sizeof(a->d[0]));
    else if (clear != 0)
        OPENSSL_clear_free(a->d, a->dmax * sizeof(a->d[0]));
    else
        OPENSSL_free(a->d);
}

/*
 * This is an internal function that should not be used in applications. It
 * ensures that 'b' has enough room for a 'words' word number and initialises
 * any unused part of b->d with leading zeros. It is mostly used by the
 * various BIGNUM routines. If there is an error, NULL is returned. If not,
 * 'b' is returned.
 */

__device__ BIGNUM *bn_expand2(BIGNUM *b, int words)
{
    if (words > b->dmax) {
        BN_ULONG *a = bn_expand_internal(b, words);
        if (!a)
            return NULL;
        if (b->d != NULL)
            bn_free_d(b, 1);
        b->d = a;
        b->dmax = words;
    }

    return b;
}

__device__ BIGNUM *bn_wexpand(BIGNUM *a, int words)
{
    return (words <= a->dmax) ? a : bn_expand2(a, words);
}

/*
 * In respect to shift factor the execution time is invariant of
 * |n % BN_BITS2|, but not |n / BN_BITS2|. Or in other words pre-condition
 * for constant-time-ness is |n < BN_BITS2| or |n / BN_BITS2| being
 * non-secret.
 */
__device__ int bn_lshift_fixed_top(BIGNUM *r, const BIGNUM *a, int n)
{
    int i, nw;
    unsigned int lb, rb;
    BN_ULONG *t, *f;
    BN_ULONG l, m, rmask = 0;

    assert(n >= 0);

    bn_check_top_by_alex(r);
    bn_check_top_by_alex(a);

    nw = n / BN_BITS2;
    if (bn_wexpand(r, a->top + nw + 1) == NULL)
        return 0;

    if (a->top != 0) {
        lb = (unsigned int)n % BN_BITS2;
        rb = BN_BITS2 - lb;
        rb %= BN_BITS2;            /* say no to undefined behaviour */
        rmask = (BN_ULONG)0 - rb;  /* rmask = 0 - (rb != 0) */
        rmask |= rmask >> 8;
        f = &(a->d[0]);
        t = &(r->d[nw]);
        l = f[a->top - 1];
        t[a->top] = (l >> rb) & rmask;
        for (i = a->top - 1; i > 0; i--) {
            m = l << lb;
            l = f[i - 1];
            t[i] = (m | ((l >> rb) & rmask)) & BN_MASK2;
        }
        t[0] = (l << lb) & BN_MASK2;
    } else {
        /* shouldn't happen, but formally required */
        r->d[nw] = 0;
    }
    if (nw != 0)
        memset(r->d, 0, sizeof(*t) * nw);

    r->neg = a->neg;
    r->top = a->top + nw + 1;
    r->flags |= BN_FLG_FIXED_TOP;

    return 1;
}

#if defined(BN_LLONG) && defined(BN_DIV2W)

__device__ BN_ULONG bn_div_words(BN_ULONG h, BN_ULONG l, BN_ULONG d)
{
    return ((BN_ULONG)(((((BN_ULLONG) h) << BN_BITS2) | l) / (BN_ULLONG) d));
}

#else

/* Divide h,l by d and return the result. */
/* I need to test this some more :-( */
BN_ULONG bn_div_words(BN_ULONG h, BN_ULONG l, BN_ULONG d)
{
    BN_ULONG dh, dl, q, ret = 0, th, tl, t;
    int i, count = 2;

    if (d == 0)
        return BN_MASK2;

    i = BN_num_bits_word(d);
    assert((i == BN_BITS2) || (h <= (BN_ULONG)1 << i));

    i = BN_BITS2 - i;
    if (h >= d)
        h -= d;

    if (i) {
        d <<= i;
        h = (h << i) | (l >> (BN_BITS2 - i));
        l <<= i;
    }
    dh = (d & BN_MASK2h) >> BN_BITS4;
    dl = (d & BN_MASK2l);
    for (;;) {
        if ((h >> BN_BITS4) == dh)
            q = BN_MASK2l;
        else
            q = h / dh;

        th = q * dh;
        tl = dl * q;
        for (;;) {
            t = h - th;
            if ((t & BN_MASK2h) ||
                ((tl) <= ((t << BN_BITS4) | ((l & BN_MASK2h) >> BN_BITS4))))
                break;
            q--;
            th -= dh;
            tl -= dl;
        }
        t = (tl >> BN_BITS4);
        tl = (tl << BN_BITS4) & BN_MASK2h;
        th += t;

        if (l < tl)
            th++;
        l -= tl;
        if (h < th) {
            h += d;
            q--;
        }
        h -= th;

        if (--count == 0)
            break;

        ret = q << BN_BITS4;
        h = ((h << BN_BITS4) | (l >> BN_BITS4)) & BN_MASK2;
        l = (l & BN_MASK2l) << BN_BITS4;
    }
    ret |= q;
    return ret;
}
#endif                          /* !defined(BN_LLONG) && defined(BN_DIV2W) */

__device__ void mul_by_alex(BN_ULONG *rp, BN_ULONG a, BN_ULONG bl, BN_ULONG bh, BN_ULONG c) {
  BN_ULONG l, h;
  
  h = a;
  l = (h & BN_MASK2);
  h >>= 32;

  BN_ULONG bl_lo = bl & BN_MASK2;
  BN_ULONG bl_hi = bl >> 32;
  
  BN_ULONG al_lo = l & BN_MASK2; 
  BN_ULONG al_hi = l >> 32;

  BN_ULONG t1 = bl_lo * al_lo;
  BN_ULONG t2 = bl_hi * al_lo + (t1 >> 32);
  BN_ULONG t3 = bl_lo * al_hi + (t2 & BN_MASK2);

  *rp = (t1 & BN_MASK2) + (t3 << 32);
  
  h += (t2 >> 32) + (t3 >> 32) + c;
  c = h >> 32;
  h &= BN_MASK2;
}

__device__ BN_ULONG bn_sub_words(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b,
                      int n)
{
    BN_ULONG t1, t2;
    int c = 0;

    assert(n >= 0);
    if (n <= 0)
        return (BN_ULONG)0;

#ifndef OPENSSL_SMALL_FOOTPRINT
    while (n & ~3) {
        t1 = a[0];
        t2 = (t1 - c) & BN_MASK2;
        c  = (t2 > t1);
        t1 = b[0];
        t1 = (t2 - t1) & BN_MASK2;
        r[0] = t1;
        c += (t1 > t2);
        t1 = a[1];
        t2 = (t1 - c) & BN_MASK2;
        c  = (t2 > t1);
        t1 = b[1];
        t1 = (t2 - t1) & BN_MASK2;
        r[1] = t1;
        c += (t1 > t2);
        t1 = a[2];
        t2 = (t1 - c) & BN_MASK2;
        c  = (t2 > t1);
        t1 = b[2];
        t1 = (t2 - t1) & BN_MASK2;
        r[2] = t1;
        c += (t1 > t2);
        t1 = a[3];
        t2 = (t1 - c) & BN_MASK2;
        c  = (t2 > t1);
        t1 = b[3];
        t1 = (t2 - t1) & BN_MASK2;
        r[3] = t1;
        c += (t1 > t2);
        a += 4;
        b += 4;
        r += 4;
        n -= 4;
    }
#endif
    while (n) {
        t1 = a[0];
        t2 = (t1 - c) & BN_MASK2;
        c  = (t2 > t1);
        t1 = b[0];
        t1 = (t2 - t1) & BN_MASK2;
        r[0] = t1;
        c += (t1 > t2);
        a++;
        b++;
        r++;
        n--;
    }
    return c;
}

__device__ BN_ULONG bn_mul_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w)
{
    BN_ULONG c1 = 0;
    BN_ULONG c2 = 0;

    assert(num >= 0);
    if (num <= 0)
        return c1;

# ifndef OPENSSL_SMALL_FOOTPRINT
    while (num & ~3) {
        mul(rp[0], ap[0], w, c1, c2); // modified
        mul(rp[1], ap[1], w, c1, c2); // modified
        mul(rp[2], ap[2], w, c1, c2); // modified
        mul(rp[3], ap[3], w, c1, c2); // modified
        ap += 4;
        rp += 4;
        num -= 4;
    }
# endif
    while (num) {
        mul(rp[0], ap[0], w, c1, c2); // modified
        ap++;
        rp++;
        num--;
    }
    return c1;
}

/*
 * In respect to shift factor the execution time is invariant of
 * |n % BN_BITS2|, but not |n / BN_BITS2|. Or in other words pre-condition
 * for constant-time-ness for sufficiently[!] zero-padded inputs is
 * |n < BN_BITS2| or |n / BN_BITS2| being non-secret.
 */
__device__ int bn_rshift_fixed_top(BIGNUM *r, const BIGNUM *a, int n)
{
    int i, top, nw;
    unsigned int lb, rb;
    BN_ULONG *t, *f;
    BN_ULONG l, m, mask;

    bn_check_top_by_alex(r);
    bn_check_top_by_alex(a);

    assert(n >= 0);

    nw = n / BN_BITS2;
    if (nw >= a->top) {
        /* shouldn't happen, but formally required */
        BN_zero(r);
        return 1;
    }

    rb = (unsigned int)n % BN_BITS2;
    lb = BN_BITS2 - rb;
    lb %= BN_BITS2;            /* say no to undefined behaviour */
    mask = (BN_ULONG)0 - lb;   /* mask = 0 - (lb != 0) */
    mask |= mask >> 8;
    top = a->top - nw;
    if (r != a && bn_wexpand(r, top) == NULL)
        return 0;

    t = &(r->d[0]);
    f = &(a->d[nw]);
    l = f[0];
    for (i = 0; i < top - 1; i++) {
        m = f[i + 1];
        t[i] = (l >> rb) | ((m << lb) & mask);
        l = m;
    }
    t[i] = l >> rb;

    r->neg = a->neg;
    r->top = top;
    r->flags |= BN_FLG_FIXED_TOP;

    return 1;
}

#ifdef BN_LLONG
__device__ BN_ULONG bn_add_words(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b,
                      int n)
{
    BN_ULLONG ll = 0;

    assert(n >= 0);
    if (n <= 0)
        return (BN_ULONG)0;

# ifndef OPENSSL_SMALL_FOOTPRINT
    while (n & ~3) {
        ll += (BN_ULLONG) a[0] + b[0];
        r[0] = (BN_ULONG)ll & BN_MASK2;
        ll >>= BN_BITS2;
        ll += (BN_ULLONG) a[1] + b[1];
        r[1] = (BN_ULONG)ll & BN_MASK2;
        ll >>= BN_BITS2;
        ll += (BN_ULLONG) a[2] + b[2];
        r[2] = (BN_ULONG)ll & BN_MASK2;
        ll >>= BN_BITS2;
        ll += (BN_ULLONG) a[3] + b[3];
        r[3] = (BN_ULONG)ll & BN_MASK2;
        ll >>= BN_BITS2;
        a += 4;
        b += 4;
        r += 4;
        n -= 4;
    }
# endif
    while (n) {
        ll += (BN_ULLONG) a[0] + b[0];
        r[0] = (BN_ULONG)ll & BN_MASK2;
        ll >>= BN_BITS2;
        a++;
        b++;
        r++;
        n--;
    }
    return (BN_ULONG)ll;
}
#else                           /* !BN_LLONG */
BN_ULONG bn_add_words(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b,
                      int n)
{
    BN_ULONG c, l, t;

    assert(n >= 0);
    if (n <= 0)
        return (BN_ULONG)0;

    c = 0;
# ifndef OPENSSL_SMALL_FOOTPRINT
    while (n & ~3) {
        t = a[0];
        t = (t + c) & BN_MASK2;
        c = (t < c);
        l = (t + b[0]) & BN_MASK2;
        c += (l < t);
        r[0] = l;
        t = a[1];
        t = (t + c) & BN_MASK2;
        c = (t < c);
        l = (t + b[1]) & BN_MASK2;
        c += (l < t);
        r[1] = l;
        t = a[2];
        t = (t + c) & BN_MASK2;
        c = (t < c);
        l = (t + b[2]) & BN_MASK2;
        c += (l < t);
        r[2] = l;
        t = a[3];
        t = (t + c) & BN_MASK2;
        c = (t < c);
        l = (t + b[3]) & BN_MASK2;
        c += (l < t);
        r[3] = l;
        a += 4;
        b += 4;
        r += 4;
        n -= 4;
    }
# endif
    while (n) {
        t = a[0];
        t = (t + c) & BN_MASK2;
        c = (t < c);
        l = (t + b[0]) & BN_MASK2;
        c += (l < t);
        r[0] = l;
        a++;
        b++;
        r++;
        n--;
    }
    return (BN_ULONG)c;
}
#endif                          /* !BN_LLONG */

/*
 * It's argued that *length* of *significant* part of divisor is public.
 * Even if it's private modulus that is. Again, *length* is assumed
 * public, but not *value*. Former is likely to be pre-defined by
 * algorithm with bit granularity, though below subroutine is invariant
 * of limb length. Thanks to this assumption we can require that |divisor|
 * may not be zero-padded, yet claim this subroutine "constant-time"(*).
 * This is because zero-padded dividend, |num|, is tolerated, so that
 * caller can pass dividend of public length(*), but with smaller amount
 * of significant limbs. This naturally means that quotient, |dv|, would
 * contain correspongly less significant limbs as well, and will be zero-
 * padded accordingly. Returned remainder, |rm|, will have same bit length
 * as divisor, also zero-padded if needed. These actually leave sign bits
 * in ambiguous state. In sense that we try to avoid negative zeros, while
 * zero-padded zeros would retain sign.
 *
 * (*) "Constant-time-ness" has two pre-conditions:
 *
 *     - availability of constant-time bn_div_3_words;
 *     - dividend is at least as "wide" as divisor, limb-wise, zero-padded
 *       if so required, which shouldn't be a privacy problem, because
 *       divisor's length is considered public;
 */
__device__ int bn_div_fixed_top(BIGNUM *dv, BIGNUM *rm, const BIGNUM *num,
                     const BIGNUM *divisor, BN_CTX *ctx)
{
    int norm_shift, i, j, loop;
    BIGNUM *tmp, *snum, *sdiv, *res;
    BN_ULONG *resp, *wnum, *wnumtop;
    BN_ULONG d0, d1;
    int num_n, div_n, num_neg;

    assert(divisor->top > 0 && divisor->d[divisor->top - 1] != 0);

    bn_check_top_by_alex(num);
    bn_check_top_by_alex(divisor);
    bn_check_top_by_alex(dv);
    bn_check_top_by_alex(rm);

    BN_CTX_start(ctx);
    res = (dv == NULL) ? BN_CTX_get(ctx) : dv;
    tmp = BN_CTX_get(ctx);
    snum = BN_CTX_get(ctx);
    sdiv = BN_CTX_get(ctx);
    if (sdiv == NULL)
        goto err;

    /* First we normalise the numbers */
    if (!BN_copy(sdiv, divisor))
        goto err;
    norm_shift = bn_left_align(sdiv);
    sdiv->neg = 0;
    /*
     * Note that bn_lshift_fixed_top's output is always one limb longer
     * than input, even when norm_shift is zero. This means that amount of
     * inner loop iterations is invariant of dividend value, and that one
     * doesn't need to compare dividend and divisor if they were originally
     * of the same bit length.
     */
    if (!(bn_lshift_fixed_top(snum, num, norm_shift)))
        goto err;

    div_n = sdiv->top;
    num_n = snum->top;

    if (num_n <= div_n) {
        /* caller didn't pad dividend -> no constant-time guarantee... */
        if (bn_wexpand(snum, div_n + 1) == NULL)
            goto err;
        memset(&(snum->d[num_n]), 0, (div_n - num_n + 1) * sizeof(BN_ULONG));
        snum->top = num_n = div_n + 1;
    }

    loop = num_n - div_n;
    /*
     * Lets setup a 'window' into snum This is the part that corresponds to
     * the current 'area' being divided
     */
    wnum = &(snum->d[loop]);
    wnumtop = &(snum->d[num_n - 1]);

    /* Get the top 2 words of sdiv */
    d0 = sdiv->d[div_n - 1];
    d1 = (div_n == 1) ? 0 : sdiv->d[div_n - 2];

    /* Setup quotient */
    if (!bn_wexpand(res, loop))
        goto err;
    num_neg = num->neg;
    res->neg = (num_neg ^ divisor->neg);
    res->top = loop;
    res->flags |= BN_FLG_FIXED_TOP;
    resp = &(res->d[loop]);

    /* space for temp */
    if (!bn_wexpand(tmp, (div_n + 1)))
        goto err;

    for (i = 0; i < loop; i++, wnumtop--) {
        BN_ULONG q, l0;
        /*
         * the first part of the loop uses the top two words of snum and sdiv
         * to calculate a BN_ULONG q such that | wnum - sdiv * q | < sdiv
         */
# if defined(BN_DIV3W)
        q = bn_div_3_words(wnumtop, d1, d0);
# else
        BN_ULONG n0, n1, rem = 0;

        n0 = wnumtop[0];
        n1 = wnumtop[-1];
        if (n0 == d0)
            q = BN_MASK2;
        else {                  /* n0 < d0 */
            BN_ULONG n2 = (wnumtop == wnum) ? 0 : wnumtop[-2];
#  ifdef BN_LLONG
            BN_ULLONG t2;

#   if defined(BN_LLONG) && defined(BN_DIV2W) && !defined(bn_div_words)
            q = (BN_ULONG)(((((BN_ULLONG) n0) << BN_BITS2) | n1) / d0);
#   else
            q = bn_div_words(n0, n1, d0);
#   endif

#   ifndef REMAINDER_IS_ALREADY_CALCULATED
            /*
             * rem doesn't have to be BN_ULLONG. The least we
             * know it's less that d0, isn't it?
             */
            rem = (n1 - q * d0) & BN_MASK2;
#   endif
            t2 = (BN_ULLONG) d1 *q;

            for (;;) {
                if (t2 <= ((((BN_ULLONG) rem) << BN_BITS2) | n2))
                    break;
                q--;
                rem += d0;
                if (rem < d0)
                    break;      /* don't let rem overflow */
                t2 -= d1;
            }
#  else                         /* !BN_LLONG */
            BN_ULONG t2l, t2h;

            q = bn_div_words(n0, n1, d0);
#   ifndef REMAINDER_IS_ALREADY_CALCULATED
            rem = (n1 - q * d0) & BN_MASK2;
#   endif

#   if defined(BN_UMULT_LOHI)
            BN_UMULT_LOHI(t2l, t2h, d1, q);
#   elif defined(BN_UMULT_HIGH)
            t2l = d1 * q;
            t2h = BN_UMULT_HIGH(d1, q);
#   else
            {
                BN_ULONG ql, qh;
                t2l = LBITS(d1);
                t2h = HBITS(d1);
                ql = LBITS(q);
                qh = HBITS(q);
                mul64(t2l, t2h, ql, qh); /* t2=(BN_ULLONG)d1*q; */
            }
#   endif

            for (;;) {
                if ((t2h < rem) || ((t2h == rem) && (t2l <= n2)))
                    break;
                q--;
                rem += d0;
                if (rem < d0)
                    break;      /* don't let rem overflow */
                if (t2l < d1)
                    t2h--;
                t2l -= d1;
            }
#  endif                        /* !BN_LLONG */
        }
# endif                         /* !BN_DIV3W */

        l0 = bn_mul_words(tmp->d, sdiv->d, div_n, q);
        tmp->d[div_n] = l0;
        wnum--;
        /*
         * ignore top values of the bignums just sub the two BN_ULONG arrays
         * with bn_sub_words
         */
        l0 = bn_sub_words(wnum, wnum, tmp->d, div_n + 1);
        q -= l0;
        /*
         * Note: As we have considered only the leading two BN_ULONGs in
         * the calculation of q, sdiv * q might be greater than wnum (but
         * then (q-1) * sdiv is less or equal than wnum)
         */
        for (l0 = 0 - l0, j = 0; j < div_n; j++)
            tmp->d[j] = sdiv->d[j] & l0;
        l0 = bn_add_words(wnum, wnum, tmp->d, div_n);
        (*wnumtop) += l0;
        assert((*wnumtop) == 0);

        /* store part of the result */
        *--resp = q;
    }
    /* snum holds remainder, it's as wide as divisor */
    snum->neg = num_neg;
    snum->top = div_n;
    snum->flags |= BN_FLG_FIXED_TOP;

    if (rm != NULL && bn_rshift_fixed_top(rm, snum, norm_shift) == 0)
        goto err;

    BN_CTX_end(ctx);
    return 1;
 err:
    bn_check_top_by_alex(rm);
    BN_CTX_end(ctx);
    return 0;
}

__device__ void bn_correct_top(BIGNUM *a)
{
    BN_ULONG *ftl;
    int tmp_top = a->top;

    if (tmp_top > 0) {
        for (ftl = &(a->d[tmp_top]); tmp_top > 0; tmp_top--) {
            ftl--;
            if (*ftl != 0)
                break;
        }
        a->top = tmp_top;
    }
    if (a->top == 0)
        a->neg = 0;
    a->flags &= ~BN_FLG_FIXED_TOP;
    bn_pollute(a);
}

/*-
 * BN_div computes  dv := num / divisor, rounding towards
 * zero, and sets up rm  such that  dv*divisor + rm = num  holds.
 * Thus:
 *     dv->neg == num->neg ^ divisor->neg  (unless the result is zero)
 *     rm->neg == num->neg                 (unless the remainder is zero)
 * If 'dv' or 'rm' is NULL, the respective value is not returned.
 */
__device__ int BN_div(BIGNUM *dv, BIGNUM *rm, const BIGNUM *num, const BIGNUM *divisor,
           BN_CTX *ctx)
{
    int ret;

    if (BN_is_zero(divisor)) {
        // ERR_raise(ERR_LIB_BN, BN_R_DIV_BY_ZERO);
        printf("BN_div: Divide by zero error\n");
        return 0;
    }

    /*
     * Invalid zero-padding would have particularly bad consequences so don't
     * just rely on bn_check_top() here (bn_check_top() works only for
     * BN_DEBUG builds)
     */
    if (divisor->d[divisor->top - 1] == 0) {
        // ERR_raise(ERR_LIB_BN, BN_R_NOT_INITIALIZED);
        printf("BN_div: Not initialized error\n");
        return 0;
    }

    ret = bn_div_fixed_top(dv, rm, num, divisor, ctx);

    if (ret) {
        if (dv != NULL)
            bn_correct_top(dv);
        if (rm != NULL)
            bn_correct_top(rm);
    }

    return ret;
}