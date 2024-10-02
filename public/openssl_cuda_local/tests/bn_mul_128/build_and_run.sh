# clear
rm -f program
# nvcc public_openssl_cuda_local.cu -arch=sm_86 -I/home/alex/projects/avax-pw-crack/public/openssl_cuda_local/include/ -o program  -lbignum -lcrypto
# nvcc -I/path/to/openssl/include -L/path/to/openssl/lib -lcrypto your_program.cu -o your_program
# nvcc \
#     --ptxas-options=-v \
#     -lineinfo \
#     -lcrypto \
#     test.cu \
#     -arch=sm_86 \
#     -I/home/alex/projects/avax-pw-crack/public/openssl_cuda_local/include/ \
#     -o program 2> build.log

nvcc \
    --threads 8 \
    --ptxas-options=-v \
    -lineinfo \
    -lcrypto \
    -g \
    test.cu \
    -arch=sm_86 \
    -use_fast_math \
    -I/home/alex/projects/avax-pw-crack/public/openssl_cuda_local/include/ \
    -o program 2> build.log

cat build.log
# print count of 'error' in build.log
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