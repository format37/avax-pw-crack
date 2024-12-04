clear
export LD_LIBRARY_PATH=/usr/lib64:$LD_LIBRARY_PATH
# To determine this path, build your openssl library with
# sudo ./Configure --prefix=/usr --debug --openssldir=/usr/lib/ssl shared zlib
# make -j$(nproc)
# sudo make install >> run.log 2>&1
# And find the libcrypto.so.3 folder in the run.log

rm -rf program
g++ \
    main.c \
    -std=c++11 \
    -g -O0 -fno-inline \
    -I /usr/local/openssl-debug/include \
    -I ../json \
    -L /usr/local/openssl-debug/lib \
    -Wl,-rpath,/usr/local/openssl-debug/lib \
    -Wl,--enable-new-dtags \
    -l:libcrypto.so.3 \
    -o program 2> build.log
cat build.log

rm -rf run.log

echo "Checking which libcrypto is being used:" >> run.log 2>&1
ldd program | grep libcrypto >> run.log 2>&1

echo "### Running the program:" >> run.log 2>&1
# valgrind \
#     --tool=callgrind \
#     --callgrind-out-file=callgrind.out.15134 \
    ./program \
    >> run.log 2>&1
cat run.log
