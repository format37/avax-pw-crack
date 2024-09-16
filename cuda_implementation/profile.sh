# sudo apt install dbus
# dbus-launch

# Get the start time
start_time=$(date +%s.%N)
# Print the current date
echo Start profiling: $(date)
/opt/nvidia/nsight-compute/2024.1.1/ncu --nvtx --verbose --export report --force-overwrite --set full ./program >> profiler.log
# /opt/nvidia/nsight-compute/2024.1.1/ncu --nvtx --verbose --export report --force-overwrite ./program >> profiler.log

# Get the end time
end_time=$(date +%s.%N)
echo End: $(date)

# Calculate the runtime
runtime=$(echo "$end_time - $start_time" | bc)

# cat run.log

# Display the runtime
echo "Profile runtime: $runtime seconds"