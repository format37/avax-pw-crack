#!/bin/bash
set -e

# Build the application
nvcc \
    --threads 8 \
    main.cu \
    -arch=sm_86 \
    -std=c++17 \
    -O3 \
    -use_fast_math \
    -I ./include \
    -I ./json \
    -o program 2> logs/build.log

start_time=$(date +%s.%N)
echo Start execution: $(date)

# Run the application
./program

end_time=$(date +%s.%N)
echo End: $(date)
runtime=$(echo "$end_time - $start_time" | bc)

echo "Shell runtime: $runtime seconds"