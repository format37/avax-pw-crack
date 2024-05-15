# clear
rm -f program
# nvcc public_openssl_cuda_local.cu -arch=sm_86 -I/home/alex/projects/avax-pw-crack/public/openssl_cuda_local/include/ -o program  -lbignum -lcrypto
# -arch=sm_86 # NVIDIA GeForce RTX 4090
# -arch=sm_61 # NVIDIA GeForce GTX 1080 Ti
# -G \
# gcc program.c -I/home/alex/projects/avax-pw-crack/public/simple_c/tests/bech32/include -o program -std=c99 -lcrypto >> build.log
gcc test.c -o program -std=c99 >> build.log
# nvcc \
#     -diag-suppress 1444 \
#     --generate-line-info \
#     -lcufft \
#     -g test.cu \
#     -arch=sm_61 \
#     -I/home/alex/projects/cuda-samples/Samples/2_Concepts_and_Techniques/interval \
#     -o program 2> build.log
# -I/home/alex/projects/avax-pw-crack/public/openssl_cuda_local/include/ \
cat build.log
# print count of 'error' in build.log
echo "Errors: $(grep -c error build.log)"