# CPU Image Build
FROM ubuntu:22.04 as cpu

# Install build essentials and dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    g++ \
    libssl-dev \
    nlohmann-json3-dev \
    bc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source files
COPY openssl/main.c .
COPY openssl/child_key.h .

# Build CPU version
RUN g++ \
    main.c \
    -std=c++11 \
    -I ../json \
    -l:libcrypto.so.3 \
    -o program

# Using shell form for timestamp calculation
CMD ["/bin/bash", "-c", "start_time=$(date +%s.%N) && ./program && end_time=$(date +%s.%N) && echo \"Execution time: $(echo \"$end_time - $start_time\" | bc) seconds\""]

# GPU Image Build
FROM nvidia/cuda:12.3.1-devel-ubuntu22.04 as gpu

# Add build argument for CUDA architecture (will be set during build time)
ARG CUDA_ARCH
ENV CUDA_ARCH=${CUDA_ARCH}

# Install build essentials and dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    g++ \
    libssl-dev \
    nlohmann-json3-dev \
    bc \
    ccache \
    && rm -rf /var/lib/apt/lists/*

# Configure ccache
ENV PATH="/usr/lib/ccache:${PATH}"
ENV CCACHE_DIR=/ccache
ENV CCACHE_MAXSIZE=10G

# Set CUDA home and path
ENV CUDA_HOME=/usr/local/cuda
ENV PATH=${CUDA_HOME}/bin:${PATH}
ENV LD_LIBRARY_PATH=${CUDA_HOME}/lib64:${LD_LIBRARY_PATH}

# Create necessary directories
WORKDIR /app
RUN mkdir -p logs

# Copy source files
COPY cuda/main.cu .
COPY cuda/include include/

# Build with nvcc using ccache (with architecture from build arg)
RUN ccache nvcc \
    --threads $(nproc) \
    main.cu \
    -arch=${CUDA_ARCH} \
    -std=c++17 \
    -O3 \
    -use_fast_math \
    -Xcompiler -pipe \
    -I ./include \
    -o program 2> logs/build.log || (cat logs/build.log && exit 1)

# Using shell form for timestamp calculation
CMD ["/bin/bash", "-c", "echo \"GPU Device: $(nvidia-smi --query-gpu=name --format=csv,noheader)\" && start_time=$(date +%s.%N) && ./program && end_time=$(date +%s.%N) && echo \"Execution time: $(echo \"$end_time - $start_time\" | bc) seconds\""]