# sudo /usr/local/cuda-12.2/nsight-compute-2023.2.1/target/linux-desktop-glibc_2_11_3-x64/ncu --config-file off --export ./profile_1.dat --force-overwrite --target-processes all --set full ./program
# sudo /usr/local/cuda-12.2/nsight-compute-2023.2.1/target/linux-desktop-glibc_2_11_3-x64/ncu --config-file off --export ./profile_1.dat --force-overwrite --target-processes all --set full --replay-mode range ./program
sudo /opt/nvidia/nsight-compute/2024.1.1/target/linux-desktop-glibc_2_11_3-x64/ncu --config-file off --export /home/alex/profiler --force-overwrite --filter-mode per-launch-config --set full ./program