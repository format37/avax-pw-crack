clear
rm -f program
g++ \
    test.c \
    -g \
    -Wno-deprecated-declarations \
    -std=c++11 \
    -lssl \
    -lcrypto \
    -I ../json \
    -I /home/alex/projects/openssl/crypto/bn/ \
    -I /home/alex/projects/openssl/include/ \
    -o program 2> build.log
# g++ test.c -g -Wno-deprecated-declarations -std=c++11 -lssl -lcrypto -I /home/alex/projects/openssl/include/ -I /home/alex/projects/openssl/crypto/bn/ -o program
cat build.log

rm -rf run.log

start_time=$(date +%s.%N)
echo Start execution: $(date)
valgrind \
    --tool=callgrind \
    ./program \    
    >> run.log

# Enable core dumps
ulimit -c unlimited

end_time=$(date +%s.%N)
runtime=$(echo "$end_time - $start_time" | bc)

cat run.log

echo "Shell runtime: $runtime seconds"