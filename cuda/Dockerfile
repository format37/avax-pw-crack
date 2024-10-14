# Use an official NVIDIA CUDA base image with Ubuntu 22.04
FROM nvidia/cuda:11.8.0-devel-ubuntu22.04

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
    && rm -rf /var/lib/apt/lists/*

# Install a newer GCC version
RUN add-apt-repository ppa:ubuntu-toolchain-r/test -y \
    && apt-get update \
    && apt-get install -y gcc-11 g++-11 \
    && apt-get install -y bc \
    && update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-11 110 \
    --slave /usr/bin/g++ g++ /usr/bin/g++-11 \
    && rm -rf /var/lib/apt/lists/*

# Copy the entrypoint script into the container
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Set the entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]
