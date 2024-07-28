# clear
rm -f program
# gcc program.c -o program -lcrypto
gcc public_openssl_c.c -g -o program -std=c99 -lcrypto
