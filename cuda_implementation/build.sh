clear
rm -f program
# nvcc public_openssl_cuda_local.cu -arch=sm_86 -I/home/alex/projects/avax-pw-crack/public/openssl_cuda_local/include/ -o program  -lbignum -lcrypto
# -arch=sm_86 # NVIDIA GeForce RTX 4090
# -arch=sm_61 # NVIDIA GeForce GTX 1080 Ti
# -diag-suppress 1444 \

export CUDA_NVCC_EXECUTABLE="ccache nvcc"

# Get the start time
start_time=$(date +%s.%N)
# Print the current date
echo Start building: $(date)

# -g \ # Generate host code debug information
# -G \ # Generate device code debug information
# -O0 \ # Disable optimizations
nvcc \
    --threads 8 \
    -O3 \
    main.cu \
    -arch=sm_86 \
    -I/home/alex/projects/avax-pw-crack/public/openssl_cuda_local/include/ \
    -lineinfo \
    -use_fast_math \
    -o program 2> build.log

cat build.log
# print count of 'error' in build.log
echo "Errors: $(grep -c error build.log)"

# Get the end time
end_time=$(date +%s.%N)
echo End: $(date)

# Calculate the runtime
runtime=$(echo "$end_time - $start_time" | bc)

# cat run.log

# Display the runtime
echo "Build runtime: $runtime seconds"