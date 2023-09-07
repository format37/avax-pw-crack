__device__ int string_compare(const char* str1, const char* str2, int length) {
    for (int i = 0; i < length; i++) {
        if (str1[i] != str2[i]) {
            return 0;
        }
    }
    return 1;
}

__global__ void my_kernel(
    char* computed_addresses,
    char* passphrases,
    char* target_addresses,
    char* result
    ) 
    {
    int idx = threadIdx.x + blockIdx.x * blockDim.x;
    int LINE_LENGTH_ADDR = 45;
    int LINE_LENGTH_PASS = 10;
    if (idx < 2310) {
        for (int target_idx = 0; target_idx < 2; target_idx++) { // TODO: Set count of target addresses
            // Compare the computed address with the target address
            if (string_compare(&computed_addresses[idx * LINE_LENGTH_ADDR], &target_addresses[target_idx * LINE_LENGTH_ADDR], LINE_LENGTH_ADDR)) {
                // Print that match was found at idx
                printf("CUDA: Match found at idx %d\n", idx);
                // Match found, set the result to the corresponding passphrase
                for (int i = 0; i < LINE_LENGTH_PASS; i++) {
                    result[i] = passphrases[idx + i];
                }                
            }
        }
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