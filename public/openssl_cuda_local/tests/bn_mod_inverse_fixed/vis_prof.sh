#!/bin/bash

# Set the desired GPU device ID (0, 1, 2, etc.)
export CUDA_VISIBLE_DEVICES=1

# sudo nvvp
sudo CUDA_VISIBLE_DEVICES=1 nvvp -vm /usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java ./program