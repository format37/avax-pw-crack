export CUDA_VISIBLE_DEVICES=0

rm -rf run.log
# ./program >> run.log
# cat run.log
# Get the start time
start_time=$(date +%s.%N)

./program >> run.log

# Get the end time
end_time=$(date +%s.%N)

# Calculate the runtime
runtime=$(echo "$end_time - $start_time" | bc)

# cat run.log

# Display the runtime
echo "Shell runtime: $runtime seconds"