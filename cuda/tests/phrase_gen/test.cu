#include <cuda_runtime.h>
#include <stdio.h>

#define MAX_PASSPHRASE_LENGTH 8

unsigned long long get_variant_id(const char* s) {
    const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 !@#$%^&*()-_=+[]{};:'\",.<>?/\\|~";
    int base = 94;
    int length = (int)strlen(s);

    unsigned long long offset = 0;
    unsigned long long value = 0;

    // Compute offsets for all shorter lengths
    for (int i = 1; i < length; i++) {
        unsigned long long count = 1;
        for (int j = 0; j < i; j++) {
            count *= base;
        }
        offset += count;
    }

    // Convert the current string to a base-94 number
    for (int i = 0; i < length; i++) {
        const char* pos = strchr(alphabet, s[i]);
        if (pos != NULL) {
            int index = (int)(pos - alphabet);
            value = value * base + index;
        }
    }

    // Final ID is offset + computed base-94 value
    return offset + value;
}

__device__ void find_letter_variant(unsigned long long variant_id, char* result) {
    const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 !@#$%^&*()-_=+[]{};:'\",.<>?/\\|~";
    const int base = 94;

    // Clear result
    for (int i = 0; i < MAX_PASSPHRASE_LENGTH; i++) {
        result[i] = '\0';
    }

    // Determine length by finding which range variant_id falls into
    int length = 1;
    unsigned long long total_count = 0;
    while (true) {
        unsigned long long count = 1;
        for (int j = 0; j < length; j++) {
            count *= base;
        }
        
        if (variant_id < total_count + count) {
            variant_id -= total_count;
            break;
        } else {
            total_count += count;
            length++;
            if (length > MAX_PASSPHRASE_LENGTH) {
                // Safety check: if too large, clamp
                length = MAX_PASSPHRASE_LENGTH;
                break;
            }
        }
    }

    // Decode variant_id as a base-94 number into 'length' characters
    unsigned long long temp = variant_id;
    for (int i = length - 1; i >= 0; i--) {
        int remainder = (int)(temp % base);
        temp /= base;
        result[i] = alphabet[remainder];
        if (i == 0) break; // to avoid infinite loop since i is unsigned
    }
}

__global__ void generate_variants_kernel(unsigned long long start_id, unsigned long long end_id) {
    char result[MAX_PASSPHRASE_LENGTH];
    unsigned long long current_id = start_id;
    
    while (current_id <= end_id) {
        find_letter_variant(current_id, result);
        printf("%s\n", result);
        current_id++;
    }
}

int main() {
    const char* start_phrase = "A";
    const char* end_phrase = "CC";
    
    // Convert strings to variant IDs on host
    unsigned long long start_id = get_variant_id(start_phrase);
    unsigned long long end_id = get_variant_id(end_phrase);
    
    printf("Starting variant generation from ID %llu to %llu\n", start_id, end_id);
    
    // Launch kernel with 1 block and 1 thread for testing
    generate_variants_kernel<<<1, 1>>>(start_id, end_id);
    
    // Wait for kernel to finish
    cudaDeviceSynchronize();
    
    // Check for errors
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("CUDA error: %s\n", cudaGetErrorString(err));
        return -1;
    }
    
    return 0;
}