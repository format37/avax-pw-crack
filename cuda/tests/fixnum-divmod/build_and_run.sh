# clear
rm -f program

# Get the start time
start_time=$(date +%s.%N)
# Print the current date
echo Start building: $(date)

nvcc \
    -I/home/alex/projects/cuda-fixnum/src/ \
    test.cu \
    -arch=sm_86 \
    -o program 2> build.log

cat build.log
echo "Errors: $(grep -c error build.log)"

# Get the end time
end_time=$(date +%s.%N)
echo End: $(date)
# Calculate the runtime
runtime=$(echo "$end_time - $start_time" | bc)
# Display the runtime
echo "Build runtime: $runtime seconds\n"

rm -rf run.log

# Get the start time
start_time=$(date +%s.%N)
# Print the current date
echo Start execution: $(date)

./program >> run.log
cat run.log

# Get the end time
end_time=$(date +%s.%N)
echo End: $(date)
# Calculate the runtime
runtime=$(echo "$end_time - $start_time" | bc)
# Display the runtime
echo "Shell runtime: $runtime seconds"
