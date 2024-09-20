// compute_sha256_test.cu

#include <stdio.h>
#include <cuda_runtime.h>
#include "sha256.h"
#include <openssl/sha.h>
#include <string.h>

#define MAX_MESSAGE_LEN 64 // Adjust as needed
#define SHA256_DIGEST_SIZE 32

// Define some test data
struct TestVector {
    const char* message;
    uint32_t message_len;
    uint8_t expected_hash[SHA256_DIGEST_LENGTH];
};

// Compute expected hashes using OpenSSL
void compute_sha256_host(const uint8_t* msg, uint32_t msg_len, uint8_t* outputHash) {
    SHA256(msg, msg_len, outputHash);
}

// CUDA kernel function
__global__ void kernel_compute_sha256(uint8_t *d_messages, uint32_t *d_message_lens, uint8_t *d_output_hashes, int max_message_len, int num_tests) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= num_tests) return;

    uint8_t *message = d_messages + idx * max_message_len;
    uint32_t message_len = d_message_lens[idx];
    uint8_t *output_hash = d_output_hashes + idx * SHA256_DIGEST_SIZE;

    // Call compute_sha256
    compute_sha256(message, message_len, output_hash);
}

int main() {
    #ifdef BN_128
        printf("\nBN_128\n");
    #else
        printf("\nBN_64\n");
    #endif
    // Define test vectors
    TestVector test_vectors[] = {
        {"", 0, {0}}, // Empty string
        {"abc", 3, {0}}, // "abc"
        {"hello world", 11, {0}}, // "hello world"
        {"The quick brown fox jumps over the lazy dog", 43, {0}},
        {"1234567890", 10, {0}},
        // Add more test cases as needed
    };

    int num_tests = sizeof(test_vectors) / sizeof(TestVector);

    // Compute expected hashes on host
    for (int i = 0; i < num_tests; ++i) {
        compute_sha256_host((const uint8_t*)test_vectors[i].message, test_vectors[i].message_len, test_vectors[i].expected_hash);
    }

    // Now, allocate device memory for input messages and output hashes

    // Allocate device memory for messages and output hashes

    uint8_t *d_messages;
    uint32_t *d_message_lens;
    uint8_t *d_output_hashes;

    size_t messages_buffer_size = num_tests * MAX_MESSAGE_LEN * sizeof(uint8_t);
    size_t output_hashes_buffer_size = num_tests * SHA256_DIGEST_SIZE * sizeof(uint8_t);
    size_t message_lens_buffer_size = num_tests * sizeof(uint32_t);

    // Allocate device memory
    cudaMalloc((void**)&d_messages, messages_buffer_size);
    cudaMalloc((void**)&d_message_lens, message_lens_buffer_size);
    cudaMalloc((void**)&d_output_hashes, output_hashes_buffer_size);

    // Prepare host buffers to copy to device

    uint8_t *h_messages = (uint8_t*)malloc(messages_buffer_size);
    uint32_t *h_message_lens = (uint32_t*)malloc(message_lens_buffer_size);

    // Initialize h_messages and h_message_lens

    memset(h_messages, 0, messages_buffer_size); // Initialize to zero
    for (int i = 0; i < num_tests; ++i) {
        memcpy(h_messages + i * MAX_MESSAGE_LEN, test_vectors[i].message, test_vectors[i].message_len);
        h_message_lens[i] = test_vectors[i].message_len;
    }

    // Copy messages and message lengths to device

    cudaMemcpy(d_messages, h_messages, messages_buffer_size, cudaMemcpyHostToDevice);
    cudaMemcpy(d_message_lens, h_message_lens, message_lens_buffer_size, cudaMemcpyHostToDevice);

    // Launch kernel to compute SHA256 hashes

    // Each thread computes SHA256 for one message

    int threads_per_block = 256;
    int num_blocks = (num_tests + threads_per_block - 1) / threads_per_block;

    kernel_compute_sha256<<<num_blocks, threads_per_block>>>(d_messages, d_message_lens, d_output_hashes, MAX_MESSAGE_LEN, num_tests);

    // Wait for kernel to finish
    cudaDeviceSynchronize();

    // Check for errors
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("CUDA Error: %s\n", cudaGetErrorString(err));
    }

    // Copy output hashes back to host
    uint8_t *h_output_hashes = (uint8_t*)malloc(output_hashes_buffer_size);
    cudaMemcpy(h_output_hashes, d_output_hashes, output_hashes_buffer_size, cudaMemcpyDeviceToHost);

    // Now compare computed hashes with expected hashes

    for (int i = 0; i < num_tests; ++i) {
        uint8_t *computed_hash = h_output_hashes + i * SHA256_DIGEST_SIZE;
        uint8_t *expected_hash = test_vectors[i].expected_hash;

        // Compare
        if (memcmp(computed_hash, expected_hash, SHA256_DIGEST_SIZE) == 0) {
            printf("Test %d PASSED\n", i);
        } else {
            printf("Test %d FAILED\n", i);
            // Print expected and computed hashes
            printf("Message: \"%s\"\n", test_vectors[i].message);
            printf("Expected: ");
            for (int j = 0; j < SHA256_DIGEST_SIZE; ++j) {
                printf("%02x", expected_hash[j]);
            }
            printf("\nComputed: ");
            for (int j = 0; j < SHA256_DIGEST_SIZE; ++j) {
                printf("%02x", computed_hash[j]);
            }
            printf("\n");
        }
    }

    // Free device memory
    cudaFree(d_messages);
    cudaFree(d_message_lens);
    cudaFree(d_output_hashes);

    // Free host memory
    free(h_messages);
    free(h_message_lens);
    free(h_output_hashes);

    return 0;
}
