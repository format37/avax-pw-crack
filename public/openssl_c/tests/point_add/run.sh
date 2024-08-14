start_time=$(date +%s.%N)
# Print the current date
echo Start: $(date)
./program
# Get the end time
end_time=$(date +%s.%N)
echo End: $(date)

# Calculate the runtime
runtime=$(echo "$end_time - $start_time" | bc)

# cat run.log

# Display the runtime
echo "Shell runtime: $runtime seconds"