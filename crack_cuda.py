import os
import numpy as np
import pycuda.driver as cuda
import pycuda.autoinit
from pycuda.compiler import SourceModule
import pycuda.driver as drv
from pycuda import gpuarray
import json


class CudaProcessor:
    def __init__(self, mnemonic, target_addresses, device_id=0, path='data_0', kernel_file='crack.cu'):
        self.mnemonic = mnemonic
        self.target_addresses = target_addresses
        self.device_id = device_id
        self.path = path
        self.kernel_file = kernel_file
        self.result = '0123456789'
        self._initialize_cuda()
        
    def _initialize_cuda(self):
        try:
            drv.init()
            self.dev = drv.Device(self.device_id)
            self.ctx = self.dev.make_context()
            
            # Read and compile the CUDA code
            with open(self.kernel_file, 'r') as f:
                cuda_code = f.read()
            
            include_dirs = ['/home/alex/projects/avax-pw-crack/include/']
            mod = SourceModule(
                cuda_code,
                arch='sm_86',
                include_dirs=include_dirs
                )
            
            # Get the CUDA function
            self.my_kernel = mod.get_function("my_kernel")
            
        except Exception as e:
            print(f"An error occurred during CUDA initialization: {e}")
            exit()
        
    def load_data(self):
        # computed_addresses
        computed_addresses = sorted([f for f in os.listdir(self.path) if f.startswith("computed_addresses")])
        
        N = len(computed_addresses) * 10
        LINE_LENGTH = 45

        h_lines = np.empty((N, LINE_LENGTH), dtype='S1')

        count = 0
        for filename in computed_addresses:
            with open(os.path.join(self.path, filename), 'r') as f:
                for line in f:
                    # print(filename, count, len(line.strip()))
                    h_lines[count] = list(line.strip())
                    count += 1
                    if count >= N:
                        break
        self.computed_addresses_gpu = gpuarray.to_gpu(h_lines)
        
        # passphrases
        passphrases = sorted([f for f in os.listdir(self.path) if f.startswith("passphrases")])

        N = len(passphrases)
        LINE_LENGTH = 10

        h_lines = np.empty((N, LINE_LENGTH), dtype='S1')

        count = 0
        for filename in passphrases:
            with open(os.path.join(self.path, filename), 'r') as f:
                for line in f:
                    # print(filename, count, len(line.strip()))
                    h_lines[count] = list(line.strip())
                    count += 1
                    if count >= N:
                        break
        # print last h_lines
        self.passphrases_gpu = gpuarray.to_gpu(h_lines)

        # target_addresses
        N = len(self.target_addresses)
        LINE_LENGTH = 45  # or whatever the length should be
        h_target_addresses = np.empty((N, LINE_LENGTH), dtype='S1')
        for idx, address in enumerate(self.target_addresses):
            h_target_addresses[idx] = list(address.ljust(LINE_LENGTH, '\0'))  # null-padding if needed
        self.target_addresses_gpu = gpuarray.to_gpu(h_target_addresses)

        # result
        self.result_gpu = gpuarray.to_gpu(np.array(list(self.result), dtype='S1'))

        # mnemonic
        N = 1
        LINE_LENGTH = len(self.mnemonic)
        h_mnemonic = np.empty((N, LINE_LENGTH), dtype='S1')
        h_mnemonic[0] = list(self.mnemonic)
        self.mnemonic_gpu = gpuarray.to_gpu(h_mnemonic)
        

    def run_kernel(self):
        block_size = 256
        N = self.computed_addresses_gpu.size // 45  # Assuming each line is 45 bytes
        grid_size = int(np.ceil(N / block_size))
        
        self.my_kernel(
            self.mnemonic_gpu,
            self.computed_addresses_gpu, 
            self.passphrases_gpu,
            self.target_addresses_gpu,
            np.uint8(len(self.target_addresses)),
            self.result_gpu,
            grid=(grid_size, 1, 1), 
            block=(block_size, 1, 1)
            )
    
    def read_result(self):
        result_cpu = self.result_gpu.get().tobytes().decode('ascii')
        return result_cpu.rstrip('\x00')

    def __del__(self):
        self.ctx.pop()
        self.ctx.detach()


def main():
    # Read configuration file
    with open('config.json') as json_file:
        data = json.load(json_file)
        mnemonic = data['mnemonic']
        best_guess = data['passphrase']
        p_chain_address = data['p_chain_address']

    # p_chain_address from config and manual p_chain_address
    target_addresses = [
        p_chain_address,
        'P-avax1lzvtzylmaap8z65r7r7dqe45mqd44zgztxucc9'
    ]
    print('Python mnemonic:', mnemonic)
    processor = CudaProcessor(mnemonic, target_addresses)
    # While mnemonic and passphrase are not implemented in CUDA yet,
    # we are using generated addresses and testphrases from files, generated by CPU
    processor.load_data()
    processor.run_kernel()
    # print(processor.read_result())
    print('Done')


if __name__ == '__main__':
    main()
