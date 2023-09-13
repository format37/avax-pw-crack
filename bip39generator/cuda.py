import numpy as np
from pycuda import gpuarray
import pycuda.autoinit
from pycuda.compiler import SourceModule
import os

# Function to add hyphens to the hex string after every 4 bytes (8 characters)
def add_hyphens_to_hex(hex_str):
    return '-'.join([hex_str[i:i+8] for i in range(0, len(hex_str), 8)])

# Load and compile the extended CUDA kernel code
kernel_file_path = "kernel.cu"  # Replace with the actual path
mod = SourceModule(
    open(kernel_file_path, 'r').read(), 
    arch='sm_86'
    )
    # include_dirs=[os.getcwd()]

# Retrieve the kernel function
pbkdf2_hmac_sha512_kernel = mod.get_function("Bip39SeedGenerator")

# Prepare output buffer to receive the derived key (seed)
derived_key_host = np.empty(64, dtype=np.uint8)

# Transfer the derived key buffer to the GPU
derived_key_gpu = gpuarray.to_gpu(derived_key_host)

# Call the kernel function (using a single thread for demonstration)
pbkdf2_hmac_sha512_kernel(block=(1,1,1))

# Copy the derived key back to the host
derived_key_host = derived_key_gpu.get()

# derived_key_host now contains the 64-byte seed generated from the mnemonic and passphrase
print('\nLength of derived key:', len(derived_key_host))
print("Derived Key:", derived_key_host)
seed_bytes = bytearray(derived_key_host)
# print("seed_bytes:", seed_bytes)
hex_result = seed_bytes.hex()
hex_result_with_hyphens = add_hyphens_to_hex(hex_result)
print('result:', hex_result_with_hyphens)
