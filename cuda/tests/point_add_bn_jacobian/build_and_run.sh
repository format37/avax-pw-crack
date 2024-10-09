clear

rm -f program

nvcc \
    --ptxas-options=-v \
    -lineinfo \
    -lcrypto \
    test.cu \
    -arch=sm_86 \
    -I include \
    -o program 2> build.log

cat build.log
echo "Errors: $(grep -c error build.log)"

start_time=$(date +%s.%N)
echo Start execution: $(date)

rm -rf run.log
./program >> run.log
cat run.log

end_time=$(date +%s.%N)
echo End: $(date)
runtime=$(echo "$end_time - $start_time" | bc)
echo "Shell runtime: $runtime seconds"