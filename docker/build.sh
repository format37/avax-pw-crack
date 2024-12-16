#!/bin/bash

# Function to build Docker image
build_image() {
    local arch=$1
    local image_name="avax:${arch}"
    
    echo "Building Docker image for architecture: ${arch}"
    echo "Image name: ${image_name}"
    
    # Move up one directory to include cuda folder in build context
    cd ..
    
    # Build the Docker image with build argument
    docker build \
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

# Main script

# Check if architecture is provided
if [ $# -ne 1 ]; then
    echo "Usage: $0 <architecture>"
    echo "Please provide a CUDA architecture (e.g., sm_86)"
    exit 1
fi

arch=$1
build_image "$arch"