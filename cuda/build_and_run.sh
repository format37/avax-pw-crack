clear
rm -f program

export CUDA_NVCC_EXECUTABLE="ccache nvcc"

# --fmad=false \ # Disable use of fma instructions
# -O3 \ # Enable optimizations
# -O0 \ # Disable optimizations
# --ptxas-options=-v \
# -lineinfo \ # generates debug line information that allows Nsight Compute to map performance metrics back to specific lines
# -g \ # Generate host code debug information
# -G \ # Generate device code debug information
# -maxrregcount 64 \ # Set the maximum number of registers that GPU kernel function can use
# -arch=sm_89 \ # 4090
# -arch=sm_86 \ # 4090
# -arch=sm_80 \ # A100

# --ptxas-options=-v \
# -lineinfo \

# nvcc \
#     --threads $(nproc) \
#     main.cu \
#     -arch=sm_86 \
#     -std=c++17 \
#     -O3 \
#     -use_fast_math \
#     -I ./include \
#     -I ../json \
#     -o program 2> logs/build.log

# First, create a precompiled header
# echo "Creating precompiled header"
# nvcc -x cu -arch=sm_86 -I ./include -I ../json common_headers.h -o common_headers.h.gch

# Install ccache if not already installed
# sudo apt-get install ccache  # For Ubuntu/Debian

start_time=$(date +%s.%N)
echo Start building: $(date)
echo "Building the program"
# -G -g \ # for quick building
ccache nvcc \
    --threads $(nproc) \
    main.cu \
    --ptxas-options=-v \
    -lineinfo \
    -arch=sm_89 \
    -std=c++17 \
    -O3 \
    -use_fast_math \
    -Xcompiler -pipe \
    -I ./include \
    -I ../json \
    -o program 2> logs/build.log

cat logs/build.log
echo "Errors: $(grep -c error logs/build.log)"

end_time=$(date +%s.%N)
echo End: $(date)
runtime=$(echo "$end_time - $start_time" | bc)
echo "Build runtime: $runtime seconds\n"

# export CUDA_VISIBLE_DEVICES=0

rm -rf logs/run.log
start_time=$(date +%s.%N)
echo Start execution: $(date)

./program >> logs/run.log
cat logs/run.log

end_time=$(date +%s.%N)
echo End: $(date)
runtime=$(echo "$end_time - $start_time" | bc)

echo "Shell runtime: $runtime seconds"