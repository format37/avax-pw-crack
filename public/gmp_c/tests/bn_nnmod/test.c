#include <gmp.h>
#include <stdlib.h>
#include <stdio.h>

int main() {   
    
    mpz_t a, n, remainder;

    mpz_init_set_str(a, "-2d5971788066012bb9df77e2c7a41dba052181e3741e833878e39ee6aa40ef8e", 16);
    mpz_init_set_str(n, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    mpz_init(remainder);

    gmp_printf("a: %Zx\n", a);
    gmp_printf("n: %Zx\n", n);
    mpz_mod(remainder, a, n);
    gmp_printf("remainder: %Zx\n", remainder);

    return 0;
}
