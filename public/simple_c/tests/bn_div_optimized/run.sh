rm -rf run.log

start_time=$(date +%s.%N)
./program >> run.log
end_time=$(date +%s.%N)

# Calculate the runtime
runtime=$(echo "$end_time - $start_time" | bc)

cat run.log

# Display the runtime
echo "\nShell runtime: $runtime seconds"