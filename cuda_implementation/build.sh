# Get the start time
start_time=$(date +%s.%N)
# Print the current date
echo Start building: $(date)

# clear
rm -f program
# nvcc public_openssl_cuda_local.cu -arch=sm_86 -I/home/alex/projects/avax-pw-crack/public/openssl_cuda_local/include/ -o program  -lbignum -lcrypto
# nvcc -I/path/to/openssl/include -L/path/to/openssl/lib -lcrypto your_program.cu -o your_program
# -lcrypto \
# -maxrregcount 64 \
nvcc \
    --ptxas-options=-v \
    -lineinfo \
    main.cu \
    -arch=sm_86 \
    -I/home/alex/projects/avax-pw-crack/public/openssl_cuda_local/include/ \
    -o program 2> build.log

cat build.log
# print count of 'error' in build.log
echo "Errors: $(grep -c error build.log)"

# # Get the end time
# end_time=$(date +%s.%N)
# echo End: $(date)

# # Calculate the runtime
# runtime=$(echo "$end_time - $start_time" | bc)

# # cat run.log

# # Display the runtime
# echo "Build runtime: $runtime seconds\n"

# rm -rf run.log
# # ./program >> run.log
# # cat run.log
# # Get the start time
# start_time=$(date +%s.%N)
# # Print the current date
# echo Start profiling: $(date)