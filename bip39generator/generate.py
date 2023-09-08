import numpy as np
from pycuda import gpuarray
import pycuda.autoinit
from pycuda.compiler import SourceModule

# Load and compile the extended CUDA kernel code
kernel_file_path = "extended_pbkdf2_hmac_sha512_kernel.cu"  # Replace with the actual path
mod = SourceModule(open(kernel_file_path, 'r').read(), arch='sm_86')

# Retrieve the kernel function
pbkdf2_hmac_sha512_kernel = mod.get_function("pbkdf2_hmac_sha512_from_mnemonic_and_passphrase")

# Prepare output buffer to receive the derived key (seed)
derived_key_host = np.empty(64, dtype=np.uint8)

# Transfer the derived key buffer to the GPU
derived_key_gpu = gpuarray.to_gpu(derived_key_host)

# Call the kernel function (using a single thread for demonstration)
pbkdf2_hmac_sha512_kernel(block=(1,1,1))

# Copy the derived key back to the host
derived_key_host = derived_key_gpu.get()

# derived_key_host now contains the 64-byte seed generated from the mnemonic and passphrase
print("Derived Key:", derived_key_host)