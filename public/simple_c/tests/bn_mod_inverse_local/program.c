#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#define MAX_BIGNUM_WORDS 4

void reverse_order(BN_ULONG test_values_a[][MAX_BIGNUM_WORDS], BN_ULONG test_values_b[][MAX_BIGNUM_WORDS], size_t num_rows) {
    for (size_t i = 0; i < num_rows; i++) {
        for (size_t j = 0; j < MAX_BIGNUM_WORDS / 2; j++) {
            BN_ULONG temp_a = test_values_a[i][j];
            test_values_a[i][j] = test_values_a[i][MAX_BIGNUM_WORDS - 1 - j];
            test_values_a[i][MAX_BIGNUM_WORDS - 1 - j] = temp_a;

            BN_ULONG temp_b = test_values_b[i][j];
            test_values_b[i][j] = test_values_b[i][MAX_BIGNUM_WORDS - 1 - j];
            test_values_b[i][MAX_BIGNUM_WORDS - 1 - j] = temp_b;
        }
    }
}

void print_bn(const char* label, const BIGNUM* bn) {
    char* bn_str = BN_bn2hex(bn);
    int i = 0;
    while (bn_str[i] == '0' && bn_str[i+1] != '\0') {
        i++;
    }
    printf("%s: %s\n", label, &bn_str[i]);
    OPENSSL_free(bn_str);
}

void set_bignum_words(BIGNUM *bn, const BN_ULONG *words, int num_words) {
    BN_zero(bn);
    for (int i = 0; i < num_words; ++i) {
        BN_add_word(bn, words[i]);
        if (i < num_words - 1) {
            BN_lshift(bn, bn, BN_BITS2);
        }
    }
}

void bn_mod_inverse_with_prints(BIGNUM *result, BIGNUM *a, BIGNUM *n, BN_CTX *ctx) {
    printf("++ bn_mod_inverse ++\n");
    print_bn(">> a", a);
    print_bn(">> n", n);
    print_bn(">> result", result);

    BIGNUM *r = BN_new();
    BIGNUM *nr = BN_new();
    print_bn("[bn_mod_inverse pre_bn_nnmod] a", a);
    print_bn("[bn_mod_inverse pre_bn_nnmod] n", n);
    print_bn("[bn_mod_inverse pre_bn_nnmod] nr", nr);
    BN_nnmod(nr, a, n, ctx);
    print_bn("[bn_mod_inverse post_bn_nnmod] nr", nr);


    if (BN_is_zero(nr)) {
        printf("No modular inverse exists\n");
        BN_zero(result);
        BN_free(r);
        BN_free(nr);
        return;
    }

    BIGNUM *t = BN_new();
    BIGNUM *nt = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *tmp = BN_new();
    BIGNUM *tmp2 = BN_new();

    BN_zero(t);
    BN_one(nt);
    BN_copy(r, n);
    unsigned int counter = 0;
    while (!BN_is_zero(nr)) {
        printf("\n### Iteration %d\n", counter);
        print_bn("\n[bn_mod_inverse pre_bn_div] r", r);
        print_bn("[bn_mod_inverse pre_bn_div] nr", nr); // CHECK
        print_bn("[bn_mod_inverse pre_bn_div] tmp", tmp);
        print_bn("[bn_mod_inverse pre_bn_div] q", q);

        BN_div(q, tmp, r, nr, ctx);
        BN_copy(tmp, nt);

        print_bn("\n[0] premul q", q);
        print_bn("[1] premul nt", nt);
        BN_mul(tmp2, q, nt, ctx);
        print_bn("[2] postmul nt", tmp2);
        print_bn("[3] presub t", t);
        BN_sub(tmp2, t, tmp2); // tmp2 = t - tmp2
        print_bn("[3.5] postsub tmp2", tmp2);
        BN_copy(nt, tmp2);
        print_bn("[4] postsub nt", nt);

        BN_copy(t, tmp);
        BN_copy(tmp, nr);
        print_bn("[5] premul nr", nr);
        print_bn("[6] premul q", q);
        BN_mul(tmp2, q, nr, ctx);
        print_bn("[7] postmul nr", tmp2);
        print_bn("[8] presub r", r);
        BN_sub(tmp2, r, tmp2); // tmp2 = r - tmp2
        BN_copy(nr, tmp2);
        print_bn("[9] postsub nr", nr);

        BN_copy(r, tmp);
        print_bn("\nq", q);
        print_bn("t", t);
        print_bn("nt", nt);
        print_bn("r", r);
        print_bn("nr", nr);
        counter++;
    }

    if (!BN_is_one(r)) {
        printf("No modular inverse exists\n");
        BN_zero(result);
    } else {
        if (BN_is_negative(t)) {
            printf("bn_mod_inverse negative t\n");
            BN_add(result, t, n);
        } else {
            BN_copy(result, t);
        }
    }

    BN_free(t);
    BN_free(nt);
    BN_free(r);
    BN_free(nr);
    BN_free(q);
    BN_free(tmp);
    BN_free(tmp2);
}

int main() {
    printf("++ Starting BN_mod_inverse test ++\n");
    BN_CTX *ctx = BN_CTX_new();
    
    BN_ULONG test_values_a[][MAX_BIGNUM_WORDS] = {
        {0xbfd25e8cd0364141, 0xbaaedce6af48a03b, 0xffffffffffffffe, 0xffffffffffffffff},
        {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xfffffffefffffc2f},
        {0x35c2d1fd4c7b8673, 0x478b08328cd9d5dd, 0xefec64ca64cda1c2, 0x46c86352a19fca54},
        {0x46c86352a19fca54, 0xefec64ca64cda1c2, 0x478b08328cd9d5dd, 0x35c2d1fd4c7b8673},
    };

    BN_ULONG test_values_n[][MAX_BIGNUM_WORDS] = {
        {0xcaa5c571ffccab5a, 0xad1c289591e564d3, 0x70116675aa53aa8a, 0x1b2db4c027cdbaba},
        {0x4c4619154810c1c0, 0xdaa4ddd8c73971d1, 0x59db91705f2113ce, 0x51b9885e4578874d},
        {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xfffffffefffffc2f},
        {0xfffffffefffffc2f, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff},
    };

    reverse_order(test_values_a, test_values_n, sizeof(test_values_a) / (sizeof(BN_ULONG) * MAX_BIGNUM_WORDS));

    // Number of tests defined by the number of elements in test_values_a/n arrays.
    int num_tests = sizeof(test_values_a) / sizeof(test_values_a[0]);

    for (int i = 0; i < num_tests; ++i) {
        printf("Test %d:\n", i);
        BIGNUM *a = BN_new();
        BIGNUM *n = BN_new();
        BIGNUM *mod_inverse = BN_new();

        set_bignum_words(a, test_values_a[i], MAX_BIGNUM_WORDS);
        set_bignum_words(n, test_values_n[i], MAX_BIGNUM_WORDS);

        print_bn("a", a);
        print_bn("n", n);

        bn_mod_inverse_with_prints(mod_inverse, a, n, ctx);

        if (!BN_is_zero(mod_inverse)) {
            printf("[%d] ", i);
            print_bn("Modular inverse", mod_inverse);
        }
        printf("\n");

        BN_free(a);
        BN_free(n);
        BN_free(mod_inverse);
    }

    BN_CTX_free(ctx);
    return 0;
}