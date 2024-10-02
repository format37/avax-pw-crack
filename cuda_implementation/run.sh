export CUDA_VISIBLE_DEVICES=0

rm -rf run.log
# ./program >> run.log
# cat run.log
# Get the start time
start_time=$(date +%s.%N)
# Print the current date
echo Start: $(date)

# cuda-memcheck ./program >> run.log # OK
# sudo nvvp ./program >> run.log
# ncu --set full ./program >> run.log
# nsys profile ./program >> run.log # OK
# nsys analyze -r gpu_time_util report1.sqlite # OK
./program >> run.log

# Get the end time
end_time=$(date +%s.%N)
echo End: $(date)

# Calculate the runtime
runtime=$(echo "$end_time - $start_time" | bc)

# cat run.log

# Display the runtime
echo "Shell runtime: $runtime seconds"