#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned long long BN_ULONG;

typedef struct bignum_st {
    BN_ULONG *d;
    int top;
    int dmax;
    int neg;
    int flags;
} BIGNUM;

void bn_print(const char* msg, BIGNUM* a) {
    printf("%s", msg);
    if (a->neg) {
        printf("-");
    }
    for (int i = a->top - 1; i >= 0; i--) {
        printf("%016llx ", a->d[i]);
    }
    printf("\n");
}

int bn_cmp(BIGNUM* a, BIGNUM* b) {
    if (a->neg != b->neg) {
        return a->neg ? -1 : 1;
    }

    if (a->top != b->top) {
        return a->top > b->top ? 1 : -1;
    }

    for (int i = a->top - 1; i >= 0; i--) {
        if (a->d[i] != b->d[i]) {
            return a->d[i] > b->d[i] ? 1 : -1;
        }
    }

    return 0;
}

int bn_copy(BIGNUM* dst, const BIGNUM* src) {
    if (dst->dmax < src->top) {
        // Reallocate memory if necessary
        BN_ULONG* new_d = (BN_ULONG*)realloc(dst->d, src->top * sizeof(BN_ULONG));
        if (new_d == NULL) {
            return 0;
        }
        dst->d = new_d;
        dst->dmax = src->top;
    }

    memcpy(dst->d, src->d, src->top * sizeof(BN_ULONG));
    dst->top = src->top;
    dst->neg = src->neg;

    return 1;
}

int bn_sub(BIGNUM* r, const BIGNUM* a, const BIGNUM* b) {
    int max_top = a->top > b->top ? a->top : b->top;

    if (r->dmax < max_top) {
        // Reallocate memory if necessary
        BN_ULONG* new_d = (BN_ULONG*)realloc(r->d, max_top * sizeof(BN_ULONG));
        if (new_d == NULL) {
            return 0;
        }
        r->d = new_d;
        r->dmax = max_top;
    }

    BN_ULONG borrow = 0;
    int i;
    for (i = 0; i < b->top; i++) {
        BN_ULONG diff = a->d[i] - b->d[i] - borrow;
        borrow = (diff > a->d[i]);
        r->d[i] = diff;
    }

    for (; i < a->top; i++) {
        BN_ULONG diff = a->d[i] - borrow;
        borrow = (diff > a->d[i]);
        r->d[i] = diff;
    }

    r->top = max_top;
    r->neg = borrow;

    // Remove leading zeros
    while (r->top > 0 && r->d[r->top - 1] == 0) {
        r->top--;
    }

    return 1;
}

int bn_add(BIGNUM* r, const BIGNUM* a, const BIGNUM* b) {
    int max_top = a->top > b->top ? a->top : b->top;

    if (r->dmax < max_top + 1) {
        // Reallocate memory if necessary
        BN_ULONG* new_d = (BN_ULONG*)realloc(r->d, (max_top + 1) * sizeof(BN_ULONG));
        if (new_d == NULL) {
            return 0;
        }
        r->d = new_d;
        r->dmax = max_top + 1;
    }

    BN_ULONG carry = 0;
    int i;
    for (i = 0; i < max_top; i++) {
        BN_ULONG sum = carry;
        if (i < a->top) {
            sum += a->d[i];
        }
        if (i < b->top) {
            sum += b->d[i];
        }
        r->d[i] = sum & 0xFFFFFFFFFFFFFFFF;
        carry = sum >> 64;
    }

    if (carry) {
        r->d[max_top] = carry;
        r->top = max_top + 1;
    } else {
        r->top = max_top;
    }

    r->neg = 0;

    return 1;
}

int bn_mod(BIGNUM* r, const BIGNUM* a, const BIGNUM* m) {
    BIGNUM tmp;
    tmp.d = (BN_ULONG*)malloc(m->top * sizeof(BN_ULONG));
    if (tmp.d == NULL) {
        return 0;
    }
    tmp.top = m->top;
    tmp.dmax = m->top;
    tmp.neg = 0;

    if (!bn_copy(&tmp, a)) {
        free(tmp.d);
        return 0;
    }

    while (bn_cmp(&tmp, m) >= 0) {
        if (!bn_sub(&tmp, &tmp, m)) {
            free(tmp.d);
            return 0;
        }
    }

    if (!bn_copy(r, &tmp)) {
        free(tmp.d);
        return 0;
    }

    free(tmp.d);
    return 1;
}

int bn_nnmod(BIGNUM* r, const BIGNUM* a, const BIGNUM* m) {
    if (m->top == 0) {
        return 0; // Error: division by zero
    }

    if (r == m) {
        fprintf(stderr, "BN_nnmod: ERR_R_PASSED_INVALID_ARGUMENT\n");
        return 0;
    }

    if (!bn_mod(r, a, m)) {
        return 0;
    }

    if (r->neg) {
        if (!bn_add(r, r, m)) {
            return 0;
        }
    }

    return 1;
}

int main() {
    BIGNUM a, n, r;

    // Initialize BIGNUMs
    a.d = (BN_ULONG*)malloc(4 * sizeof(BN_ULONG));
    n.d = (BN_ULONG*)malloc(4 * sizeof(BN_ULONG));
    r.d = (BN_ULONG*)malloc(4 * sizeof(BN_ULONG));

    a.top = 4;
    a.dmax = 4;
    a.neg = 1;
    a.d[0] = 0x2d5971788066012b;
    a.d[1] = 0xb9df77e2c7a41dba;
    a.d[2] = 0x052181e3741e8338;
    a.d[3] = 0x78e39ee6aa40ef8e;

    n.top = 4;
    n.dmax = 4;
    n.neg = 0;
    n.d[0] = 0xffffffffffffffff;
    n.d[1] = 0xffffffffffffffff;
    n.d[2] = 0xffffffffffffffff;
    n.d[3] = 0xfffffffefffffc2f;

    r.top = 4;
    r.dmax = 4;
    r.neg = 0;

    bn_print("a = ", &a);
    bn_print("n = ", &n);

    if (bn_nnmod(&r, &a, &n)) {
        bn_print("r = ", &r);
    } else {
        printf("Error occurred during bn_nnmod\n");
    }

    // Free memory
    free(a.d);
    free(n.d);
    free(r.d);

    return 0;
}