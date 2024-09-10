#include <cuda_runtime.h>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <stdio.h>
#include <cuda.h>
#include "bignum.h"
#define MAX_PASSPHRASE_LENGTH 10
#include "p_chain.h"
#include "nlohmann/json.hpp"
#include <cstring>

#define P_CHAIN_ADDRESS_LENGTH 45  // Assuming the p-chain address is 45 characters long
#define MAX_MNEMONIC_LENGTH 1024  // Adjust this value based on your maximum expected mnemonic length

__device__ bool d_address_found = false;
__device__ char d_address_value[P_CHAIN_ADDRESS_LENGTH + 1];
__device__ char d_passphrase_value[MAX_PASSPHRASE_LENGTH];
// __device__ const char alphabet[] = "abcdefghijklmnopqrstuvwxyz";
// __device__ const int alphabet_length = 26;

__device__ __forceinline__ void find_letter_variant(int variant_id, char* passphrase_value) {
    // Define alphabet as a constant array
    const char alphabet[] = "abcdefghijklmnopqrstuvwxyz";
    const int alphabet_length = 26;

    // Initialize first character to null terminator, rest will be filled as needed
    passphrase_value[0] = '\0';

    // Handle the special case for variant_id == 0
    if (variant_id == 0) {
        passphrase_value[0] = alphabet[0];
        passphrase_value[1] = '\0';
        return;
    }

    int result_length = 0;
    
    // Generate the passphrase
    while (variant_id > 0 && result_length < MAX_PASSPHRASE_LENGTH - 1) {  // Leave room for null terminator
        --variant_id;  // Adjust for 0-based indexing
        passphrase_value[result_length++] = alphabet[variant_id % alphabet_length];
        variant_id /= alphabet_length;
    }
    passphrase_value[result_length] = '\0';  // Ensure null termination

    // Reverse the result in-place
    int start = 0;
    int end = result_length - 1;
    while (start < end) {
        char temp = passphrase_value[start];
        passphrase_value[start] = passphrase_value[end];
        passphrase_value[end] = temp;
        ++start;
        --end;
    }
    // Check if the null terminator is in place
    // if (passphrase_value[result_length] != '\0') {
    //     printf("Null terminator not in place\n"); // TODO: Remove this debug case
    // }
}

__device__ int my_strncmp(const char* s1, const char* s2, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        if (s1[i] != s2[i]) {
            return s1[i] - s2[i];
        }
        if (s1[i] == '\0') {
            return 0;
        }
    }
    return 0;
}

// __global__ void variant_kernel(int *max_threads, unsigned long long shift) {
// __global__ void variant_kernel(int *max_threads, unsigned long long shift, const char *expected_value) {
__global__ void variant_kernel(int *max_threads, unsigned long long shift, const char *expected_value, const char *mnemonic) {
    unsigned long long idx = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned long long global_idx = idx + shift;
    
    if (idx >= *max_threads) return;
    
    char local_passphrase_value[MAX_PASSPHRASE_LENGTH] = {0};
    find_letter_variant(global_idx, local_passphrase_value);
    
    // Calculate p-chain address
    // uint8_t *mnemonic = (unsigned char *)"sell stereo useless course suffer tribe jazz monster fresh excess wire again father film sudden pelican always room attack rubber pelican trash alone cancel";

    // char expected_value[P_CHAIN_ADDRESS_LENGTH+1] = "P-avax16ygmzt8rudy57d0a6uvx0xm6eaxswjjwj3sqds"; // 32767, avlg
    // char expected_value[P_CHAIN_ADDRESS_LENGTH+1] = "P-avax1hs8j43549he3tuxd3wupp3nr0n9l3j80r4539a"; // 32768, avlh
    // char expected_value[P_CHAIN_ADDRESS_LENGTH+1] = "P-avax1f0ssty5xf2zys5hpctkljvjelq9lkgqgmnwtg6"; // 131068, gkwb
    // char expected_value[P_CHAIN_ADDRESS_LENGTH+1] = "P-avax1fduhaad247ck2rh305c9vntxrcfrecqh6gedat"; // 2147482623, fxshqkm

    // P_CHAIN_ADDRESS_STRUCT p_chain_address = restore_p_chain_address(mnemonic, local_passphrase_value);
    P_CHAIN_ADDRESS_STRUCT p_chain_address = restore_p_chain_address((uint8_t*)mnemonic, local_passphrase_value);
    
    if (my_strncmp(p_chain_address.data, expected_value, P_CHAIN_ADDRESS_LENGTH+1) == 0) {
        d_address_found = true;
        for (int i = 0; i < P_CHAIN_ADDRESS_LENGTH; i++) {
            d_address_value[i] = p_chain_address.data[i];
        }
        // Set the passphrase value
        for (int i = 0; i < MAX_PASSPHRASE_LENGTH; i++) {
            d_passphrase_value[i] = local_passphrase_value[i];
        }
        d_address_value[P_CHAIN_ADDRESS_LENGTH] = '\0';
    }
}

int main() {
    int grid_size = 128;
    int threadsPerBlock = 256;
    int h_max_threads = grid_size * threadsPerBlock;
    int *d_max_threads;
    
    // cudaMalloc((void**)&d_max_threads, sizeof(int));
    // cudaMemcpy(d_max_threads, &h_max_threads, sizeof(int), cudaMemcpyHostToDevice);

    bool h_address_found = false;
    char h_address_value[P_CHAIN_ADDRESS_LENGTH + 1];
    char h_passphrase_value[MAX_PASSPHRASE_LENGTH];

    // Read expected value from JSON file
    std::ifstream config_file("config.json");
    if (!config_file.is_open()) {
        std::cerr << "Failed to open config.json" << std::endl;
        return -1;
    }
    
    nlohmann::json config;
    config_file >> config;
    
    std::string expected_value = config["p_chain_address"];
    if (expected_value.length() != P_CHAIN_ADDRESS_LENGTH) {
        std::cerr << "Invalid p_chain_address length in config.json" << std::endl;
        return -1;
    }

    std::string mnemonic = config["mnemonic"];
    if (mnemonic.empty()) {
        std::cerr << "Mnemonic is empty in config.json" << std::endl;
        return -1;
    }
    
    char *d_expected_value;
    cudaMalloc((void**)&d_expected_value, P_CHAIN_ADDRESS_LENGTH + 1);
    cudaMemcpy(d_expected_value, expected_value.c_str(), P_CHAIN_ADDRESS_LENGTH + 1, cudaMemcpyHostToDevice);

    char *d_mnemonic;
    cudaMalloc((void**)&d_mnemonic, mnemonic.length() + 1);
    cudaMemcpy(d_mnemonic, mnemonic.c_str(), mnemonic.length() + 1, cudaMemcpyHostToDevice);
    
    // Number of iterations
    const int N = 4;
    
    for (int i = 0; i < N; i++) {
        cudaMalloc((void**)&d_max_threads, sizeof(int));
        cudaMemcpy(d_max_threads, &h_max_threads, sizeof(int), cudaMemcpyHostToDevice);

        unsigned long long shift = (unsigned long long)i * h_max_threads;
        
        // variant_kernel<<<grid_size, threadsPerBlock>>>(d_max_threads, shift);
        // variant_kernel<<<grid_size, threadsPerBlock>>>(d_max_threads, shift, d_expected_value);
        variant_kernel<<<grid_size, threadsPerBlock>>>(d_max_threads, shift, d_expected_value, d_mnemonic);
        
        cudaError_t err = cudaGetLastError();
        if (err != cudaSuccess) {
            printf("Error in iteration %d: %s\n", i, cudaGetErrorString(err));
            cudaDeviceReset();
            return -1;
        }

        cudaDeviceSynchronize();
        
        err = cudaGetLastError();
        if (err != cudaSuccess) {
            printf("Error after synchronization in iteration %d: %s\n", i, cudaGetErrorString(err));
            cudaDeviceReset();
            return -1;
        }

        cudaMemcpyFromSymbol(&h_address_found, d_address_found, sizeof(bool));
        if (h_address_found) {
            cudaMemcpyFromSymbol(h_address_value, d_address_value, P_CHAIN_ADDRESS_LENGTH + 1);
            printf("\nAddress found in iteration %d: %s\n", i, h_address_value);
            cudaMemcpyFromSymbol(h_passphrase_value, d_passphrase_value, MAX_PASSPHRASE_LENGTH);
            printf("Passphrase: %s\n", h_passphrase_value);

            std::ofstream result_file("result.txt");
            if (result_file.is_open()) {
                result_file << "Address: " << h_address_value << std::endl;
                result_file << "Passphrase: " << h_passphrase_value << std::endl;
                result_file.close();
                std::cout << "Results saved to result.txt" << std::endl;
            } else {
                std::cerr << "Unable to open result.txt for writing" << std::endl;
            }

            break;
        }
        cudaDeviceReset();
    }

    if (!h_address_found) {
        printf("\nAddress not found in any iteration\n");
    }

    cudaFree(d_max_threads);
    cudaFree(d_expected_value);
    cudaFree(d_mnemonic);
    cudaDeviceReset();

    return 0;
}