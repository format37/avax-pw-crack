# clear
rm -f program
# nvcc public_openssl_cuda_local.cu -arch=sm_86 -I/home/alex/projects/avax-pw-crack/public/openssl_cuda_local/include/ -o program  -lbignum -lcrypto
nvcc \
    -diag-suppress 1444 \
    -G \
    -g test.cu \
    -arch=sm_86 \
    -I/home/alex/projects/avax-pw-crack/public/openssl_cuda_local/include/ \
    -o program 2> build.log

cat build.log
# print count of 'error' in build.log
echo "Errors: $(grep -c error build.log)"