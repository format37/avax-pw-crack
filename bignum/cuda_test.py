import numpy as np
from pycuda import gpuarray
import pycuda.autoinit
from pycuda.compiler import SourceModule
import os

# Function to add hyphens to the hex string after every 4 bytes (8 characters)
def add_hyphens_to_hex(hex_str):
    return '-'.join([hex_str[i:i+8] for i in range(0, len(hex_str), 8)])

# Load and compile the extended CUDA kernel code
# include_dirs = ['/mnt/hdd0/share/alex/projects/cuda_libs/']
include_dirs = ['/home/alex/projects/avax-pw-crack/bignum/include/']
# './include/utility/',
# include_dirs = []
# include_dirs=[]
# include_dirs = [os.getcwd()]
# mod = SourceModule(cuda_code, arch='sm_86', include_dirs=include_dirs)
kernel_file_path = "kernel.cu"  # Replace with the actual path
# help(SourceModule)
# exit()
with open(kernel_file_path, 'r') as f:
    cuda_code = f.read()
mod = SourceModule(
    cuda_code,
    include_dirs=include_dirs,
    arch='sm_86'
    )
    # 

# Retrieve the kernel function
pbkdf2_hmac_sha512_kernel = mod.get_function("testKernel")

# Prepare output buffer to receive the derived key (seed)
derived_key_host = np.empty(64, dtype=np.uint8)

# Transfer the derived key buffer to the GPU
derived_key_gpu = gpuarray.to_gpu(derived_key_host)

# Call the kernel function (using a single thread for demonstration)
pbkdf2_hmac_sha512_kernel(block=(1,1,1))
