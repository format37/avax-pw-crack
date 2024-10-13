clear

rm -f program

start_time=$(date +%s.%N)
echo Start building: $(date)

# nvcc \
#     --ptxas-options=-v \
#     -lineinfo \
#     -lcrypto \
#     test.cu \
#     -arch=sm_86 \
#     -I ../../include \
#     -o program 2> build.log
nvcc \
    --threads 8 \
    test.cu \
    -arch=sm_86 \
    -O3 \
    -maxrregcount 64 \
    -use_fast_math \
    -I ../../include \
    -o program 2> build.log

cat build.log
echo "Errors: $(grep -c error build.log)"

end_time=$(date +%s.%N)
echo End: $(date)
runtime=$(echo "$end_time - $start_time" | bc)
echo "Build runtime: $runtime seconds\n"

start_time=$(date +%s.%N)
echo Start execution: $(date)

rm -rf run.log
./program >> run.log
cat run.log

end_time=$(date +%s.%N)
echo End: $(date)
runtime=$(echo "$end_time - $start_time" | bc)
echo "Shell runtime: $runtime seconds"