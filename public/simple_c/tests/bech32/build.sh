# clear
rm -rf program
rm -rf build.log
# gcc program.c -o program -lcrypto
# gcc -I/home/alex/projects/avax-pw-crack/public/openssl_c_local/include test.c -o program -std=c99 -lcrypto
gcc program.c -I/home/alex/projects/avax-pw-crack/public/simple_c/tests/bech32/include -o program -std=c99 -lcrypto >> build.log
# gcc program.c -o program

cat build.log