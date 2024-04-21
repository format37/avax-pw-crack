#include <stdio.h>

int mod_inverse(int a, int n) {
    if (n == 1) {
        return -1;  // No modular inverse exists
    }
    int t = 0, nt = 1, r = n, nr = a % n;
    while (nr != 0) {
        int q = r / nr;
        int tmp = nt;
        printf("\n[0] premul q = %s0x%x\n", (q < 0) ? "-" : "", (q < 0) ? -q : q);
        printf("[1] premul nt = %s0x%x\n", (nt < 0) ? "-" : "", (nt < 0) ? -nt : nt);
        //nt = t - q * nt;
        nt = q * nt;
        // printf("postmul nt = 0x%x\n", nt);
        printf("[2] postmul nt = %s0x%x\n", (nt < 0) ? "-" : "", (nt < 0) ? -nt : nt);
        // printf("presub t = 0x%x\n", t);
        printf("[3] presub t = %s0x%x\n", (t < 0) ? "-" : "", (t < 0) ? -t : t);
        nt = t - nt;
        // printf("postsub nt = 0x%x\n", nt);
        printf("[4] postsub nt = %s0x%x\n", (nt < 0) ? "-" : "", (nt < 0) ? -nt : nt);
        t = tmp;
        tmp = nr;
        // printf("postmul nr = 0x%x\n",nr);
        printf("[5] premul nr = %s0x%x\n", (nr < 0) ? "-" : "", (nr < 0) ? -nr : nr);
        printf("[6] premul q = %s0x%x\n", (q < 0) ? "-" : "", (q < 0) ? -q : q);
        nr = q * nr;
        printf("[7] postmul nr = %s0x%x\n", (nr < 0) ? "-" : "", (nr < 0) ? -nr : nr);
        printf("[8] presub r = %s0x%x\n", (r < 0) ? "-" : "", (r < 0) ? -r : r);
        nr = r - nr;
        printf("[9] postsub nr = %s0x%x\n", (nr < 0) ? "-" : "", (nr < 0) ? -nr : nr);
        r = tmp;
        // printf("\nq = 0x%x, \nt = 0x%x, \nnt = 0x%x, \nr = 0x%x, \nnr = 0x%x\n", q, t, nt, r, nr);
        printf("\n###\nq = 0x%x, \nt = %s0x%x, \nnt = %s0x%x, \nr = %s0x%x, \nnr = %s0x%x\n", q, (t < 0) ? "-" : "", (t < 0) ? -t : t, (nt < 0) ? "-" : "", (nt < 0) ? -nt : nt, (r < 0) ? "-" : "", (r < 0) ? -r : r, (nr < 0) ? "-" : "", (nr < 0) ? -nr : nr);
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
    int a = 0x3;
    int n = 0x1;
    int inverse = mod_inverse(a, n);
    if (inverse != -1) {
        //printf("The modular inverse of %d modulo %d is %d\n", a, n, inverse);
        // Print as hex
        // printf("Modular inverse: 0x%x\n", inverse);
        printf("Modular inverse: %s0x%x\n", (inverse < 0) ? "-" : "", (inverse < 0) ? -inverse : inverse);
    } else {
        printf("No modular inverse exists for %d modulo %d\n", a, n);
        printf("inverse is %d\n", inverse);
    }
    return 0;
}