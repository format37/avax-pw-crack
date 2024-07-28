# clear
rm -f program
# gcc program.c -o program -lcrypto
# gcc -I/home/alex/projects/avax-pw-crack/public/openssl_c_local/include test.c -o program -std=c99 -lcrypto
# gcc test.c -o program
# gcc test.c -pg -o program -std=c99 -lcrypto
gcc -pg -o program test.c -std=c99 -I/usr/local/ssl/include -L/usr/local/ssl/lib -lcrypto -fprofile-arcs -ftest-coverage
