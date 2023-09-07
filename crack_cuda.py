import os
import numpy as np
import pycuda.driver as cuda
import pycuda.autoinit
from pycuda.compiler import SourceModule
import pycuda.driver as drv
from pycuda import gpuarray


class CudaProcessor:
    def __init__(self, device_id=0, path='data_0', kernel_file='crack.cu'):
        self.device_id = device_id
        self.path = path
        self.kernel_file = kernel_file
        self._initialize_cuda()
        
    def _initialize_cuda(self):
        drv.init()
        self.dev = drv.Device(self.device_id)
        self.ctx = self.dev.make_context()
        
        mod = SourceModule(open(self.kernel_file, 'r').read(), arch='sm_86')
        self.my_kernel = mod.get_function("my_kernel")
        
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
        self.passphrases_gpu = gpuarray.to_gpu(h_lines)

    def run_kernel(self):
        block_size = 256
        N = self.computed_addresses_gpu.size // 45  # Assuming each line is 45 bytes
        grid_size = int(np.ceil(N / block_size))
        
        self.my_kernel(
            self.computed_addresses_gpu, 
            self.passphrases_gpu,
            grid=(grid_size, 1, 1), 
            block=(block_size, 1, 1)
            )

    def __del__(self):
        self.ctx.pop()
        self.ctx.detach()


def main():
    processor = CudaProcessor()
    processor.load_data()
    processor.run_kernel()
    print('Done')


if __name__ == '__main__':
    main()
