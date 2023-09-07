// __constant__ char d_lines[5010 * 45];

__global__ void my_kernel(
    char* computed_addresses,
    char* passphrases
    ) 
    {
    int idx = threadIdx.x + blockIdx.x * blockDim.x;
    if (idx < 5010) {
        // Access the global memory here, e.g., d_lines_global[idx * 45]
    }
}

/* ### Datatypes ###
Length (bytes) NumPy type	CUDA type
1 np.int8	    signed char 2**7-1 == 127
2 np.int16	    short 2**15-1 == 32767
4 np.int32	    int 2**31-1 == 2147483647
8 np.int64	    long long 2**63-1 == 9223372036854775807
1 np.uint8	    unsigned char 2**8-1 == 255
2 np.uint16	    unsigned short 2**16-1 == 65535
4 np.uint32     unsigned int 2**32-1 == 4294967295
8 np.uint64     unsigned long long 2**64-1 == 18446744073709551615
4 np.float32	float 2**32-1 == 4294967295
8 np.float64    double 2**64-1 == 18446744073709551615
*/