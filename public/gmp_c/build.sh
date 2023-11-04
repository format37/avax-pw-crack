clear
rm -f program
# gcc program.c -o program -lcrypto
# gcc program.c -o program -std=c99 -lcrypto
# nvcc program.cu -arch=sm_86 -o program
gcc public_gmp_c.c -o program -lgmp
