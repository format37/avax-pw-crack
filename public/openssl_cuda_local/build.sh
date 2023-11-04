clear
rm -f program
# nvcc public_openssl_cuda_local.cu -arch=sm_86 -I/home/alex/projects/avax-pw-crack/public/openssl_cuda_local/include/ -o program  -lbignum -lcrypto
nvcc public_openssl_cuda_local.cu -arch=sm_86 -I/home/alex/projects/avax-pw-crack/public/openssl_cuda_local/include/ -o program
