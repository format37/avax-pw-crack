#!/bin/bash

# Set the desired GPU device ID (0, 1, 2, etc.)
export CUDA_VISIBLE_DEVICES=0

rm -rf run.log

# Get the start time
start_time=$(date +%s.%N)
# Print the current date
echo Start: $(date)

./program >> run.log
# cat run.log

# Get the end time
end_time=$(date +%s.%N)
echo End: $(date)

# Calculate the runtime
runtime=$(echo "$end_time - $start_time" | bc)

# cat run.log

# Display the runtime
echo "Shell runtime: $runtime seconds"
