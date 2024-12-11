#include <cuda_runtime.h>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <stdio.h>
#include <cuda.h>
#include "bignum.h"
#include "p_chain.h"
#include "nlohmann/json.hpp"
#include <cstring>
#include <string.h>
#include <limits.h>

#define MAX_PASSPHRASE_LENGTH 100 // Ledger declaration
#define MAX_ALPHABET_LENGTH 256  // Maximum possible alphabet length
#define P_CHAIN_ADDRESS_LENGTH 45  // Assuming the p-chain address is 45 characters long

// Global variables to store config
__device__ __constant__ char d_alphabet[MAX_ALPHABET_LENGTH];
__device__ __constant__ int d_alphabet_length;  // Store alphabet length in constant memory

__device__ bool d_address_found = false;
__device__ char d_address_value[P_CHAIN_ADDRESS_LENGTH + 1];
__device__ char d_passphrase_value[MAX_PASSPHRASE_LENGTH];

__device__ __constant__ char d_mnemonic[256];  // Adjust size as needed
__device__ __constant__ char d_start_passphrase[MAX_PASSPHRASE_LENGTH];
__device__ __constant__ char d_end_passphrase[MAX_PASSPHRASE_LENGTH];
__device__ __constant__ char d_expected_p_chain_address[P_CHAIN_ADDRESS_LENGTH + 1];
__device__ __constant__ unsigned long long d_start_variant_id;
__device__ __constant__ unsigned long long d_end_variant_id;

#define OVERFLOW_FLAG ULLONG_MAX

unsigned long long get_variant_id(const char* s, const char* alphabet, int alphabet_length) {
    int base = alphabet_length;
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

    // Convert the current string to a base-N number
    for (int i = 0; i < length; i++) {
        const char* pos = strchr(alphabet, s[i]);
        if (pos != NULL) {
            int index = (int)(pos - alphabet);
            value = value * base + index;
        }
    }

    return offset + value;
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

__device__ void find_letter_variant(unsigned long long variant_id, char* result) {
    extern __constant__ char d_alphabet[];
    extern __constant__ int d_alphabet_length;

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
            count *= d_alphabet_length;
        }
        
        if (variant_id < total_count + count) {
            variant_id -= total_count;
            break;
        } else {
            total_count += count;
            length++;
            if (length > MAX_PASSPHRASE_LENGTH) {
                length = MAX_PASSPHRASE_LENGTH;
                break;
            }
        }
    }

    // Decode variant_id as a base-N number into 'length' characters
    unsigned long long temp = variant_id;
    for (int i = length - 1; i >= 0; i--) {
        int remainder = (int)(temp % d_alphabet_length);
        temp /= d_alphabet_length;
        result[i] = d_alphabet[remainder];
        if (i == 0) break;
    }
}

__global__ void variant_kernel() {
    int blockId = blockIdx.x;
    int threadId = threadIdx.x;
    int globalIdx = blockId * blockDim.x + threadId;
    unsigned long long variant_id = d_start_variant_id + globalIdx;
    
    while (variant_id <= d_end_variant_id) {
        char local_passphrase_value[MAX_PASSPHRASE_LENGTH];
        find_letter_variant(variant_id, local_passphrase_value);        
        
        // Calculate p-chain address
        P_CHAIN_ADDRESS_STRUCT p_chain_address = restore_p_chain_address((uint8_t*)d_mnemonic, local_passphrase_value);
        
        if (my_strncmp(p_chain_address.data, d_expected_p_chain_address, P_CHAIN_ADDRESS_LENGTH+1) == 0) {
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
        // Early exit if address is found
        if (d_address_found) break;
        
        variant_id += gridDim.x * blockDim.x;

    }
}

int main() {
    // Get the current stack size limit
    size_t currentLimit;
    cudaError_t error = cudaDeviceGetLimit(&currentLimit, cudaLimitStackSize);
    if (error != cudaSuccess) {
        printf("Error getting current stack size limit: %s\n", cudaGetErrorString(error));
        return 1;
    }
    printf("Current stack size limit: %zu bytes\n", currentLimit);
    size_t newLimit = 1024 * 64;
    error = cudaDeviceSetLimit(cudaLimitStackSize, newLimit);
    if (error == cudaSuccess) {
        printf("Successfully set stack size limit to %zu bytes\n", newLimit);
    } else {
        printf("Failed to set stack size limit to %zu bytes. Error: %s\n", 
               newLimit, cudaGetErrorString(error));
    }

    bool h_address_found = false;
    char h_address_value[P_CHAIN_ADDRESS_LENGTH + 1];
    char h_passphrase_value[MAX_PASSPHRASE_LENGTH];

    // Read expected value from JSON file
    std::ifstream config_file("../config.json");
    if (!config_file.is_open()) {
        std::cerr << "Failed to open config.json" << std::endl;
        return -1;
    }
    
    nlohmann::json config;
    config_file >> config;

    // Read CUDA configuration parameters
    int threadsPerBlock = config["cuda"]["threadsPerBlock"];
    int blocksPerGrid = config["cuda"]["blocksPerGrid"];
    std::cout << "Using CUDA configuration:" << std::endl;
    std::cout << "  Threads per block: " << threadsPerBlock << std::endl;
    std::cout << "  Blocks per grid: " << blocksPerGrid << std::endl;

    std::string mnemonic = config["mnemonic"];
    std::string alphabet = config["alphabet"];
    std::string start_passphrase = config["start_passphrase"];
    std::string end_passphrase = config["end_passphrase"];
    std::string expected_p_chain_address = config["p_chain_address"];

    // Get alphabet length
    int alphabet_length = alphabet.length();

    // Verify alphabet length doesn't exceed maximum
    if (alphabet_length >= MAX_ALPHABET_LENGTH) {
        std::cerr << "Alphabet length exceeds maximum allowed length of " 
                  << MAX_ALPHABET_LENGTH - 1 << std::endl;
        return -1;
    }

    if (expected_p_chain_address.length() != P_CHAIN_ADDRESS_LENGTH) {
        std::cerr << "Invalid p_chain_address length in config.json" << std::endl;
        return -1;
    }
    if (mnemonic.empty()) {
        std::cerr << "Mnemonic is empty in config.json" << std::endl;
        return -1;
    }

    // Convert strings to variant IDs on host
    unsigned long long start_variant_id = get_variant_id(start_passphrase.c_str(), 
                                               alphabet.c_str(), 
                                               alphabet_length);
    unsigned long long end_variant_id = get_variant_id(end_passphrase.c_str(), 
                                             alphabet.c_str(), 
                                             alphabet_length);
    
    // Copy alphabet and its length to constant memory
    cudaMemcpyToSymbol(d_alphabet, alphabet.c_str(), alphabet_length + 1);
    cudaMemcpyToSymbol(d_alphabet_length, &alphabet_length, sizeof(int));
    
    printf("Starting variant generation from ID %llu to %llu\n", start_variant_id, end_variant_id);

    if (start_variant_id == OVERFLOW_FLAG || end_variant_id == OVERFLOW_FLAG) {
        std::cerr << "Passphrase overflow detected. The maximum passphrase is gkgwbylwrxtlpn" << std::endl;
        return -1;
    }

    std::cout << "Start variant id: " << start_variant_id << std::endl;
    std::cout << "End variant id: " << end_variant_id << std::endl;
    std::cout << "Search area: " << end_variant_id - start_variant_id + 1 << std::endl;

    // Copy data to constant memory
    cudaMemcpyToSymbol(d_mnemonic, mnemonic.c_str(), mnemonic.length() + 1);
    cudaMemcpyToSymbol(d_start_passphrase, start_passphrase.c_str(), start_passphrase.length() + 1);
    cudaMemcpyToSymbol(d_end_passphrase, end_passphrase.c_str(), end_passphrase.length() + 1);
    cudaMemcpyToSymbol(d_expected_p_chain_address, expected_p_chain_address.c_str(), expected_p_chain_address.length() + 1);
    cudaMemcpyToSymbol(d_start_variant_id, &start_variant_id, sizeof(unsigned long long));
    cudaMemcpyToSymbol(d_end_variant_id, &end_variant_id, sizeof(unsigned long long));

    std::cout << "Launching kernel with " << blocksPerGrid << " blocks and " << threadsPerBlock << " threads per block" << std::endl;
    
    // Launch kernel
    variant_kernel<<<blocksPerGrid, threadsPerBlock>>>();

    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("Error launching kernel: %s\n", cudaGetErrorString(err));
        cudaDeviceReset();
        return -1;
    }

    cudaDeviceSynchronize();

    err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("Error after synchronization: %s\n", cudaGetErrorString(err));
        cudaDeviceReset();
        return -1;
    }

    // Check if address was found
    cudaMemcpyFromSymbol(&h_address_found, d_address_found, sizeof(bool));
    if (h_address_found) {
        cudaMemcpyFromSymbol(h_address_value, d_address_value, P_CHAIN_ADDRESS_LENGTH + 1);
        printf("\nAddress found: %s\n", h_address_value);
        cudaMemcpyFromSymbol(h_passphrase_value, d_passphrase_value, MAX_PASSPHRASE_LENGTH);
        printf("Passphrase: %s\n", h_passphrase_value);

        // Save results to file
        std::ofstream result_file("result.txt");
        if (result_file.is_open()) {
            result_file << "Address: " << h_address_value << std::endl;
            result_file << "Passphrase: " << h_passphrase_value << std::endl;
            result_file.close();
            std::cout << "Results saved to result.txt" << std::endl;
        } else {
            std::cerr << "Unable to open result.txt for writing" << std::endl;
        }
    } else {
        printf("\nAddress not found\n");
    }

    // Clean up
    cudaFree(d_mnemonic);
    cudaFree(d_start_passphrase);
    cudaFree(d_end_passphrase);
    cudaFree(d_expected_p_chain_address);
    cudaDeviceReset();

    return 0;
}