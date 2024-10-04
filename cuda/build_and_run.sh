clear
rm -f program

export CUDA_NVCC_EXECUTABLE="ccache nvcc"

start_time=$(date +%s.%N)
echo Start building: $(date)

# --fmad=false \ # Disable use of fma instructions
# -O3 \ # Enable optimizations
# -O0 \ # Disable optimizations
# --ptxas-options=-v \
# -lineinfo \ # generates debug line information that allows Nsight Compute to map performance metrics back to specific lines
# -g \ # Generate host code debug information
# -G \ # Generate device code debug information
# -maxrregcount 64 \ # Set the maximum number of registers that GPU kernel function can use
# -I/home/alex/projects/avax-pw-crack/public/openssl_cuda_local/include/ \

nvcc \
    --threads 8 \
    main.cu \
    -arch=sm_86 \
    -use_fast_math \
    -I ./include \
    -I ../json \
    -o program 2> build.log

cat build.log
echo "Errors: $(grep -c error build.log)"

end_time=$(date +%s.%N)
echo End: $(date)
runtime=$(echo "$end_time - $start_time" | bc)
echo "Build runtime: $runtime seconds\n"

# export CUDA_VISIBLE_DEVICES=0

rm -rf run.log
start_time=$(date +%s.%N)
echo Start execution: $(date)

./program >> run.log
cat run.log

end_time=$(date +%s.%N)
echo End: $(date)
runtime=$(echo "$end_time - $start_time" | bc)

echo "Shell runtime: $runtime seconds"