#!/bin/bash

# Function to build GPU Docker image
build_gpu_image() {
    local arch=$1
    local image_name="avax:${arch}"
    
    echo "Building GPU Docker image for architecture: ${arch}"
    echo "Image name: ${image_name}"
    
    # Move up one directory to include cuda folder in build context
    cd ..
    
    # Build the Docker image with build argument
    docker build \
        --target gpu \
        --build-arg CUDA_ARCH="${arch}" \
        -t "${image_name}" \
        --progress=plain \
        -f docker/Dockerfile \
        .
    
    local build_status=$?
    if [ $build_status -ne 0 ]; then
        echo "Error: Docker build failed for architecture ${arch}"
        exit $build_status
    fi
    
    echo "Successfully built image: ${image_name}"
}

# Function to build CPU Docker image
build_cpu_image() {
    local image_name="avax:cpu"
    
    echo "Building CPU Docker image"
    echo "Image name: ${image_name}"
    
    # Move up one directory to include openssl folder in build context
    cd ..
    
    # Build the Docker image
    docker build \
        --target cpu \
        -t "${image_name}" \
        --progress=plain \
        -f docker/Dockerfile \
        .
    
    local build_status=$?
    if [ $build_status -ne 0 ]; then
        echo "Error: Docker build failed for CPU image"
        exit $build_status
    fi
    
    echo "Successfully built image: ${image_name}"
}

#!/bin/bash  # Make sure this line is present and the file has execute permissions

# ... existing function definitions ...

# Main script
if [ $# -ne 1 ]; then
    echo "Usage: $0 <architecture>"
    echo "Examples:"
    echo "  $0 cpu         # Build CPU image"
    echo "  $0 sm_89      # Build GPU image for CUDA architecture Ada Lovelace (see README.md for other architectures)"
    exit 1
fi

arch=$1

# Fix: Ensure proper function name is used
if [ "$arch" = "cpu" ]; then
    build_cpu_image    # Fix: Ensure this exact function name is used
else
    build_gpu_image "$arch"    # Fix: Ensure this exact function name is used
fi