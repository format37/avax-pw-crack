#include <cuda_runtime.h>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <stdio.h>
#include <cuda.h>
#include "bignum.h"
#define MAX_PASSPHRASE_LENGTH 5 // "book" test word + null terminator. DON'T FORGET TO INCREASE
#include "p_chain.h"
#include "nlohmann/json.hpp"
#include <cstring>
#include <string.h>
#include <limits.h>
#include <nvtx3/nvToolsExt.h>

#define P_CHAIN_ADDRESS_LENGTH 45  // Assuming the p-chain address is 45 characters long

__device__ bool d_address_found = false;
__device__ char d_address_value[P_CHAIN_ADDRESS_LENGTH + 1];
__device__ char d_passphrase_value[MAX_PASSPHRASE_LENGTH];

#define OVERFLOW_FLAG ULLONG_MAX

struct ThreadTiming {
    int blockIdx;
    int threadIdx;
    long long startTime;
    long long endTime;
};

unsigned long long find_variant_id(const char* s) {
    const char* alphabet = "abcdefghijklmnopqrstuvwxyz";
    int base = strlen(alphabet);
    unsigned long long result = 0;
    unsigned long long prev_result = 0;
    
    for (int i = 0; s[i] != '\0'; i++) {
        const char* pos = strchr(alphabet, s[i]);
        if (pos != NULL) {
            int index = pos - alphabet;
            
            // Check for multiplication overflow
            if (result > ULLONG_MAX / base) {
                return OVERFLOW_FLAG;
            }
            result *= base;
            
            // Check for addition overflow
            if (result > ULLONG_MAX - (index + 1)) {
                return OVERFLOW_FLAG;
            }
            result += index + 1;
            
            // Check if the value wrapped around
            if (result < prev_result) {
                return OVERFLOW_FLAG;
            }
            
            prev_result = result;
        }
    }
    
    return result;
}

// __device__ __forceinline__ void find_letter_variant(int variant_id, char* passphrase_value) {
__device__ void find_letter_variant(int variant_id, char* passphrase_value) {
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

__global__ void variant_kernel(
    unsigned long long start_variant_id,
    unsigned long long end_variant_id, 
    const char *expected_value, 
    const char *mnemonic,
    ThreadTiming *timings
) {
    int blockId = blockIdx.x;
    int threadId = threadIdx.x;
    int globalIdx = blockId * blockDim.x + threadId;
    unsigned long long variant_id = start_variant_id + globalIdx;
    
    // Record start time
    long long start_time = clock64();
    timings[globalIdx].blockIdx = blockId;
    timings[globalIdx].threadIdx = threadId;
    timings[globalIdx].startTime = start_time;
    
    while (variant_id <= end_variant_id && !d_address_found) {
        char local_passphrase_value[MAX_PASSPHRASE_LENGTH] = {0};
        find_letter_variant(variant_id, local_passphrase_value);
        
        // Calculate p-chain address
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
        // Early exit if address is found
        if (d_address_found) break;
        
        variant_id += gridDim.x * blockDim.x;
    }
    
    // Record end time
    long long end_time = clock64();
    timings[globalIdx].endTime = end_time;
}

void write_timing_to_csv(const char* filename, ThreadTiming* timings, int num_threads) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Error opening file: " << filename << std::endl;
        return;
    }
    
    file << "BlockIdx,ThreadIdx,StartTime,EndTime,Duration" << std::endl;
    
    for (int i = 0; i < num_threads; i++) {
        file << timings[i].blockIdx << ","
             << timings[i].threadIdx << ","
             << timings[i].startTime << ","
             << timings[i].endTime << ","
             << (timings[i].endTime - timings[i].startTime) << std::endl;
    }
    
    file.close();
    std::cout << "Timing data saved to " << filename << std::endl;
}

unsigned long long calculate_iterations(unsigned long long start_variant_id, unsigned long long end_variant_id, int h_max_threads) {
    unsigned long long search_area = end_variant_id - start_variant_id;
    return (search_area + h_max_threads - 1) / h_max_threads;
}

int main() {
    // int threadsPerBlock = 256;
    int threadsPerBlock = 1;
    int blocksPerGrid = 1;
    int totalThreads = threadsPerBlock * blocksPerGrid;

    // Allocate memory for timing data
    ThreadTiming *h_timings = new ThreadTiming[totalThreads];
    ThreadTiming *d_timings;
    cudaMalloc(&d_timings, totalThreads * sizeof(ThreadTiming));

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
    
    // std::string expected_value = config["p_chain_address"];
    std::string expected_value = config["p_chain_address"];
    std::string mnemonic = config["mnemonic"];
    std::string start_passphrase = config["start_passphrase"];
    std::string end_passphrase = config["end_passphrase"];

    if (expected_value.length() != P_CHAIN_ADDRESS_LENGTH) {
        std::cerr << "Invalid p_chain_address length in config.json" << std::endl;
        return -1;
    }
    if (mnemonic.empty()) {
        std::cerr << "Mnemonic is empty in config.json" << std::endl;
        return -1;
    }

    // Calculate search area
    unsigned long long start_variant_id = find_variant_id(start_passphrase.c_str());
    unsigned long long end_variant_id = find_variant_id(end_passphrase.c_str());

    if (start_variant_id == OVERFLOW_FLAG || end_variant_id == OVERFLOW_FLAG) {
        std::cerr << "Passphrase overflow detected. The maximum passphrase is gkgwbylwrxtlpn" << std::endl;
        return -1;
    }

    std::cout << "Start variant id: " << start_variant_id << std::endl;
    std::cout << "End variant id: " << end_variant_id << std::endl;
    std::cout << "Search area: " << end_variant_id - start_variant_id + 1 << std::endl;

    char *d_expected_value;
    cudaMalloc((void**)&d_expected_value, P_CHAIN_ADDRESS_LENGTH + 1);
    cudaMemcpy(d_expected_value, expected_value.c_str(), P_CHAIN_ADDRESS_LENGTH + 1, cudaMemcpyHostToDevice);

    char *d_mnemonic;
    cudaMalloc((void**)&d_mnemonic, mnemonic.length() + 1);
    cudaMemcpy(d_mnemonic, mnemonic.c_str(), mnemonic.length() + 1, cudaMemcpyHostToDevice);

    std::cout << "Launching kernel with " << blocksPerGrid << " blocks and " << threadsPerBlock << " threads per block" << std::endl;
    
    // Start NVTX range
    nvtxRangePush("KernelExecution");

    // Launch kernel
    variant_kernel<<<blocksPerGrid, threadsPerBlock>>>(
        start_variant_id, 
        end_variant_id, 
        d_expected_value, 
        d_mnemonic,
        d_timings
    );

    // End NVTX range
    nvtxRangePop();

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

    // Copy timing data back to host
    cudaMemcpy(h_timings, d_timings, totalThreads * sizeof(ThreadTiming), cudaMemcpyDeviceToHost);

    // Write timing data to CSV
    write_timing_to_csv("thread_timing.csv", h_timings, totalThreads);

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
    cudaFree(d_expected_value);
    cudaFree(d_mnemonic);
    cudaDeviceReset();

    delete[] h_timings;
    cudaFree(d_timings);

    return 0;
}