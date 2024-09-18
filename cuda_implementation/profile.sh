# sudo apt install dbus
# dbus-launch

# Get the start time
start_time=$(date +%s.%N)
# Print the current date
echo Start profiling: $(date)
# set: 
# - full: 5256 seconds
# - detailed
# - roofline
# - basic
# - pmsampling
# - nvlink
# --metrics sm__sass_average_data_live_registers,sm__sass_maximum_data_live_registers \
/opt/nvidia/nsight-compute/2024.1.1/ncu \
    --nvtx \
    --verbose \
    --export report \
    --force-overwrite \
    --set full \
    --target-processes all \
    ./program >> profiler.log
# /opt/nvidia/nsight-compute/2024.1.1/ncu --nvtx --verbose --export report --force-overwrite --target-processes all ./program >> profiler.log

# Get the end time
end_time=$(date +%s.%N)
echo End: $(date)

# Calculate the runtime
runtime=$(echo "$end_time - $start_time" | bc)

# cat run.log

# Display the runtime
echo "Profile runtime: $runtime seconds"