__device__ int string_compare(const char* str1, const char* str2, int length) {
    for (int i = 0; i < length; i++) {
        if (str1[i] != str2[i]) {
            return 0;
        }
    }
    return 1;
}

__global__ void my_kernel(
    char* mnemonic,
    char* computed_addresses,
    char* passphrases,
    char* target_addresses,
    unsigned char target_addresses_count,
    char* result
    ) 
    {
    int idx = threadIdx.x + blockIdx.x * blockDim.x;
    int LINE_LENGTH_ADDR = 45;
    int LINE_LENGTH_PASS = 10;
    int passphrase_idx = idx / 10;
    // Define the test_passphrase of length 10
    char test_passphrase[10];
    if (idx < 2310 && idx == 2200) {
        
        // === Bip39SeedGenerator ===
        // Fill the test_passphrase with the current passphrase
        for (int i = 0; i < LINE_LENGTH_PASS; i++) {
            test_passphrase[i] = passphrases[passphrase_idx * LINE_LENGTH_PASS + i];
        }
        // print the test_passphrase
        printf("test_passphrase: ");
        for (int i = 0; i < LINE_LENGTH_PASS; i++) {
            printf("%c", test_passphrase[i]);
        }


        for (int target_idx = 0; target_idx < target_addresses_count; target_idx++) {
            // Compare the computed address with the target address
            if (string_compare(&computed_addresses[idx * LINE_LENGTH_ADDR], &target_addresses[target_idx * LINE_LENGTH_ADDR], LINE_LENGTH_ADDR)) {
                // Print that match was found for idx, phrase, and target
                printf("Match found for idx %d, phrase %d, and target %d\n", idx, passphrase_idx, target_idx);
                for (int i = 0; i < LINE_LENGTH_PASS; i++) {
                    result[i] = passphrases[passphrase_idx * LINE_LENGTH_PASS + i];
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