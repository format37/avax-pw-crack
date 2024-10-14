# Use the latest NVIDIA CUDA base image with Ubuntu 22.04
FROM nvidia/cuda:12.2.2-devel-ubuntu22.04

# Set the working directory in the container
WORKDIR /app

# Install necessary packages
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    wget \
    libssl-dev \
    software-properties-common \
    nlohmann-json3-dev \
    libglu1-mesa-dev \
    freeglut3-dev \
    mesa-common-dev \
    bc \
    && rm -rf /var/lib/apt/lists/*

# Copy the entrypoint script into the container
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Set the entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]
