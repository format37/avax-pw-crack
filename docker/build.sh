#!/bin/bash

# Supported architectures
declare -A supported_archs
supported_archs=(
    ["sm_86"]="1"
    ["sm_80"]="1"
    ["sm_61"]="1"
)

# Function to validate architecture
validate_arch() {
    local arch=$1
    if [[ -z "${supported_archs[$arch]}" ]]; then
        echo "Error: Unsupported architecture '$arch'"
        echo "Supported architectures: ${!supported_archs[@]}"
        exit 1
    fi
}

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
    echo "Supported architectures: ${!supported_archs[@]}"
    exit 1
fi

arch=$1
validate_arch "$arch"
build_image "$arch"