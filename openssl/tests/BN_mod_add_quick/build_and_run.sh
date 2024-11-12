clear
export LD_LIBRARY_PATH=/usr/lib64:$LD_LIBRARY_PATH
rm -f program
rm -f build.log
    # -Wno-deprecated-declarations \
    # -g -Wall -O0 -fno-inline \
g++ \
    test.c \
    -std=c++11 \
    -g -O0 -fno-inline \
    -lssl \
    -lcrypto \
    -I ../json \
    -I /home/alex/projects/openssl_mod/crypto/bn/ \
    -I /home/alex/projects/openssl_mod/include/ \
    -Wl,-rpath,/usr/local/openssl-debug/lib \
    -Wl,--enable-new-dtags \
    -l:libcrypto.so.3 \
    -o program 2> build.log
# g++ \
#     test.c \
#     -std=c++11 \
#     -g -O0 -fno-inline \
#     -I /usr/local/openssl-debug/include \
#     -I ../json \
#     -L /usr/local/openssl-debug/lib \
#     -Wl,-rpath,/usr/local/openssl-debug/lib \
#     -Wl,--enable-new-dtags \
#     -l:libcrypto.so.3 \
#     -o program 2> build.log
cat build.log
# g++ test.c -g -Wno-deprecated-declarations -std=c++11 -lssl -lcrypto -I /home/alex/projects/openssl/include/ -I /home/alex/projects/openssl/crypto/bn/ -o program
# cat build.log

echo "Checking which libcrypto is being used:"
ldd program | grep libcrypto

rm -rf run.log

start_time=$(date +%s.%N)
echo Start execution: $(date)
valgrind \
    --tool=callgrind \
    --callgrind-out-file=callgrind.out.15134 \
    ./program \
    >> run.log 2>&1

end_time=$(date +%s.%N)
runtime=$(echo "$end_time - $start_time" | bc)

cat run.log

echo "Shell runtime: $runtime seconds"