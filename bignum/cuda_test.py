import numpy as np
from pycuda import gpuarray
import pycuda.autoinit
from pycuda.compiler import SourceModule
import os

# Load and compile the extended CUDA kernel code
include_dirs = ['/home/alex/projects/avax-pw-crack/bignum/include/']

kernel_file_path = "kernel.c"
with open(kernel_file_path, 'r') as f:
    cuda_code = f.read()

mod = SourceModule(
    cuda_code,
    arch='sm_86',
    include_dirs=include_dirs
    )

# Retrieve the kernel function
kernel = mod.get_function("testKernel")

# Call the kernel function (using a single thread for demonstration)
kernel(block=(1,1,1))
