clear
rm -f program
g++ \
    main.c \
    -g \
    -Wno-deprecated-declarations \
    -std=c++11 \
    -lssl \
    -lcrypto \
    -I ../json \
    -o program 2> build.log
# gcc \
#     main.c \
#     -g \
#     -std=c11 \
#     -lssl \
#     -lcrypto \
#     -I ../json \
#     -o program 2> build.log
cat build.log

rm -rf run.log

start_time=$(date +%s.%N)
echo Start execution: $(date)
# "sell stereo useless course suffer tribe jazz monster fresh excess wire again father film sudden pelican always room attack rubber pelican trash alone cancel" \
# "a" \
# valgrind \
#     --tool=callgrind \
#     ./program \    
#     >> run.log
./program >> run.log

# Enable core dumps
# ulimit -c unlimited
# Run the program
# strace -f  ./program >> run.log 2>&1
# gdb -ex run --args ./program
# valgrind --leak-check=full -s ./program >> run.log
# ./program >> run.log 2>&1

end_time=$(date +%s.%N)
runtime=$(echo "$end_time - $start_time" | bc)

cat run.log

echo "Shell runtime: $runtime seconds"