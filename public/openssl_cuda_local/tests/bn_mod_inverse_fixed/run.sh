#!/bin/bash

# Set the desired GPU device ID (0, 1, 2, etc.)
export CUDA_VISIBLE_DEVICES=1

rm -rf run.log

# Get the start time
start_time=$(date +%s.%N)

# Run the program and redirect output to run.log
./program >> run.log

# Get the end time
end_time=$(date +%s.%N)

# Calculate the runtime
runtime=$(echo "$end_time - $start_time" | bc)

# Display the run.log contents
cat run.log

# Display the runtime
echo "Runtime: $runtime seconds"