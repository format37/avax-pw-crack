#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#define BN_ULONG uint64_t
#define WORDS 4
#define BN_BITS2 (sizeof(BN_ULONG) * 8)
#define BN_MASK2 ((BN_ULONG)0xffffffffffffffffL)


void bn_print(const char *prefix, const BN_ULONG *a, int top)
{
    printf("%s", prefix);
    for (int i = 0; i < top; ++i) {
        printf("%016lX", a[i]);
    }
    printf("\n");
}

int bn_cmp(const BN_ULONG *a, const BN_ULONG *b, int top)
{
    for (int i = top - 1; i >= 0; --i) {
        if (a[i] > b[i])
            return 1;
        if (a[i] < b[i])
            return -1;
    }
    return 0;
}

void bn_sub(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b, int top)
{
    BN_ULONG t, c = 0;
    for (int i = 0; i < top; ++i) {
        t = a[i] - c;
        c = (t < a[i]);
        t -= b[i];
        c += (t < b[i]);
        r[i] = t;
    }
    assert(c == 0);
}

BN_ULONG bn_div_3_words(BN_ULONG n0, BN_ULONG n1, BN_ULONG n2, BN_ULONG d0, BN_ULONG d1)
{
    BN_ULONG q, r;
    uint64_t t2 = ((uint64_t)n1 << (BN_BITS2 - 64)) | n0;
    if (n2 == d0) {
        q = BN_MASK2;
        r = t2 - ((uint64_t)d0 * q);
    } else {
        q = t2 / d0;
        r = t2 % d0;
    }
    for (;;) {
        uint64_t h = ((uint64_t)r << (BN_BITS2 - 64)) | n2;
        if (q * (uint64_t)d1 > h) {
            --q;
            r += d0;
            if (r < d0)
                break;
            continue;
        }
        break;
    }
    return q;
}

int bn_div_fixed_top(BN_ULONG *dv, BN_ULONG *rm, const BN_ULONG *num, const BN_ULONG *div, int top)
{
    int i, j;
    BN_ULONG *wnum, *resp, *wnumtop;
    BN_ULONG d0, d1;
    BN_ULONG q;
    int num_n = top + 1, div_n = top;
    
    wnum = (BN_ULONG *)malloc((num_n + 1) * sizeof(BN_ULONG));
    if (wnum == NULL)
        return 0;
    
    memset(wnum, 0, (num_n + 1) * sizeof(BN_ULONG));
    memcpy(&wnum[num_n - top], num, top * sizeof(BN_ULONG));
    wnumtop = &wnum[num_n - 1];

    resp = dv;
    d0 = div[div_n - 1];
    d1 = div[div_n - 2];

    for (i = num_n - div_n; i >= 0; --i) {
        q = bn_div_3_words(wnum[i], wnum[i + 1], wnum[i + 2], d0, d1);

        BN_ULONG *tmp = (BN_ULONG *)malloc((div_n + 1) * sizeof(BN_ULONG));
        if (tmp == NULL) {
            free(wnum);
            return 0;
        }
        
        BN_ULONG l0 = 0;
        for (j = 0; j <= div_n; ++j) {
            tmp[j] = wnum[i + j];
            tmp[j] -= q * div[j] + l0;
            l0 = tmp[j] >> (BN_BITS2 - 1);
            tmp[j] &= BN_MASK2;
        }
        for (j = 0; j <= div_n; ++j)
            wnum[i + j] = tmp[j];
        
        free(tmp);
        resp[i] = q;
    }

    if (rm != NULL) {
        for (i = 0; i < div_n; ++i)
            rm[i] = wnum[i];
    }

    free(wnum);
    return 1;
}

int bn_div(const BN_ULONG *num, const BN_ULONG *div, BN_ULONG *dv, BN_ULONG *rm, int top)
{
    assert(div[top - 1] != 0);
    
    if (bn_cmp(num, div, top) < 0) {
        if (rm != NULL) {
            memcpy(rm, num, top * sizeof(BN_ULONG));
        }
        if (dv != NULL) {
            memset(dv, 0, top * sizeof(BN_ULONG));
        }
        return 1;
    }
    
    return bn_div_fixed_top(dv, rm, num, div, top);
}

int main()
{
    BN_ULONG a[WORDS] = {0x0FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE, 0xbaaedce6af48a03b, 0xbfd25e8cd0364141};
    BN_ULONG b[WORDS] = {0x1b2db4c027cdbaba, 0x70116675aa53aa8a, 0xad1c289591e564d3, 0xcaa5c571ffccab5a};

    bn_print("a = ", a, WORDS);
    bn_print("b = ", b, WORDS);

    BN_ULONG q[WORDS];
    BN_ULONG r[WORDS];
    if (!bn_div(a, b, q, r, WORDS)) {
        printf("Error: bn_div failed\n");
        return 1;
    }

    bn_print("q = ", q, WORDS);
    bn_print("r = ", r, WORDS);

    return 0;
}