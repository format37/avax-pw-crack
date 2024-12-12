FROM nvidia/cuda:12.3.1-devel-ubuntu22.04

# Add build argument for CUDA architecture
ARG CUDA_ARCH=sm_86

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

# Build with nvcc using ccache (with error handling)
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

# Using exec form with shell for better signal handling
CMD ["/bin/bash", "-c", "start_time=$(date +%s.%N) && ./program && end_time=$(date +%s.%N) && echo $start_time && echo $end_time && echo \"$end_time - $start_time\" | bc > time.txt"]