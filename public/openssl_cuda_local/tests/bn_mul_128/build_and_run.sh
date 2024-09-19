# clear
rm -f program
# nvcc public_openssl_cuda_local.cu -arch=sm_86 -I/home/alex/projects/avax-pw-crack/public/openssl_cuda_local/include/ -o program  -lbignum -lcrypto
# nvcc -I/path/to/openssl/include -L/path/to/openssl/lib -lcrypto your_program.cu -o your_program
nvcc \
    --ptxas-options=-v \
    -lineinfo \
    -lcrypto \
    test.cu \
    -arch=sm_86 \
    -I/home/alex/projects/avax-pw-crack/public/openssl_cuda_local/include/ \
    -o program 2> build.log

cat build.log
# print count of 'error' in build.log
echo "Errors: $(grep -c error build.log)"

rm -rf run.log
./program >> run.log
cat run.log
