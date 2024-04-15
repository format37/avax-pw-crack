#include <stdio.h>

int mod_inverse(int a, int n) {
    int t = 0, nt = 1, r = n, nr = a % n;
    while (nr != 0) {
        int q = r / nr;
        int tmp = nt;
        printf("\npremul q = %d\n", q);
        printf("postmul nt = %d\n", q*nt);
        nt = t - q * nt;
        printf("postsub nt = %d\n", nt);
        t = tmp;
        tmp = nr;
        printf("postmul nr = %d\n", q*nr);
        nr = r - q * nr;
        r = tmp;
        printf("q = %d, t = %d, nt = %d, r = %d, nr = %d\n", q, t, nt, r, nr);
    }
    if (r > 1) {
        return -1; // No modular inverse exists
    }
    if (t < 0) {
        t += n;
    }
    return t;
}

int main() {
    int a = 3;
    int n = 11;
    int inverse = mod_inverse(a, n);
    if (inverse != -1) {
        printf("The modular inverse of %d modulo %d is %d\n", a, n, inverse);
    } else {
        printf("No modular inverse exists for %d modulo %d\n", a, n);
    }
    return 0;
}