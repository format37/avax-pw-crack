# clear
rm -f program
# gcc program.c -o program -lcrypto
gcc -I/home/alex/projects/avax-pw-crack/public/openssl_c_local/include public_openssl_c_local.c -o program -std=c99 -lcrypto
# gcc -I/home/alex/projects/avax-pw-crack/public/openssl_c_local/include public_openssl_c_local.c -o program -std=c99
