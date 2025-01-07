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
#include <random>
#include <sstream>

#define MAX_PASSPHRASE_LENGTH 100 // Ledger declaration
#define MAX_ALPHABET_LENGTH 256  // Maximum possible alphabet length
#define P_CHAIN_ADDRESS_LENGTH 45  // Assuming the p-chain address is 45 characters long
#define MAX_RESULTS 11000000  // ~1.65GB of device memory

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
__device__ __constant__ int d_p_chain_export;

// Add these device variables for storing results
__device__ int d_result_count = 0;
__device__ struct ResultEntry {
    int globalIdx;
    unsigned long long variant_id;
    char passphrase[MAX_PASSPHRASE_LENGTH];
    char address[P_CHAIN_ADDRESS_LENGTH + 1];
} d_results[MAX_RESULTS];

#define OVERFLOW_FLAG ULLONG_MAX

// Function to generate UUID
std::string generate_uuid() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    std::uniform_int_distribution<> dis2(8, 11);

    std::stringstream ss;
    ss << std::hex;

    for (int i = 0; i < 8; i++) {
        ss << dis(gen);
    }
    ss << "-";
    for (int i = 0; i < 4; i++) {
        ss << dis(gen);
    }
    ss << "-4";  // Version 4 UUID
    for (int i = 0; i < 3; i++) {
        ss << dis(gen);
    }
    ss << "-";
    ss << dis2(gen);  // Variant byte
    for (int i = 0; i < 3; i++) {
        ss << dis(gen);
    }
    ss << "-";
    for (int i = 0; i < 12; i++) {
        ss << dis(gen);
    }

    return ss.str();
}

unsigned long long get_variant_id(const char* s, const char* alphabet, int alphabet_length) {
    int length = strlen(s);
    unsigned long long value = 0;
    
    // First, account for all shorter lengths
    for (int len = 1; len < length; len++) {
        // Calculate total variants for this length
        unsigned long long variants_for_length = 1;
        for (int i = 0; i < len; i++) {
            variants_for_length *= alphabet_length;
        }
        value += variants_for_length;
    }
    
    // Then add the value for current length
    for (int i = 0; i < length; i++) {
        const char* pos = strchr(alphabet, s[i]);
        if (pos != NULL) {
            int index = (int)(pos - alphabet);
            value += index * (unsigned long long)pow(alphabet_length, length - i - 1);
        }
    }
    
    return value;
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
    
    // Find the correct length for this variant_id
    int length = 1;
    unsigned long long accumulated = d_alphabet_length;  // variants for length 1
    unsigned long long prev_accumulated = 0;
    
    while (variant_id >= accumulated) {
        prev_accumulated = accumulated;
        length++;
        // Calculate variants for next length
        accumulated += (unsigned long long)pow(d_alphabet_length, length);
    }
    
    // Adjust variant_id to be relative to current length
    variant_id -= prev_accumulated;
    
    // Clear result
    for (int i = 0; i < MAX_PASSPHRASE_LENGTH; i++) {
        result[i] = '\0';
    }
    
    // Generate the variant for the calculated length
    for (int i = length - 1; i >= 0; i--) {
        int remainder = (int)(variant_id % d_alphabet_length);
        variant_id /= d_alphabet_length;
        result[i] = d_alphabet[remainder];
    }
    result[length] = '\0';
}

__device__ void device_strncpy(char* dest, const char* src, size_t n) {
    for (size_t i = 0; i < n && src[i] != '\0'; i++) {
        dest[i] = src[i];
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
        
        // Only store result if export is enabled
        if (d_p_chain_export) {
            int current_idx = atomicAdd(&d_result_count, 1);
            if (current_idx < MAX_RESULTS) {
                ResultEntry& entry = d_results[current_idx];
                entry.globalIdx = globalIdx;
                entry.variant_id = variant_id;
                device_strncpy(entry.passphrase, local_passphrase_value, MAX_PASSPHRASE_LENGTH);
                device_strncpy(entry.address, p_chain_address.data, P_CHAIN_ADDRESS_LENGTH);
                entry.address[P_CHAIN_ADDRESS_LENGTH] = '\0';
            }
        }
        
        // Original address matching code
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

    // Calculate start and end variant IDs including all lengths
    unsigned long long start_variant_id = get_variant_id(start_passphrase.c_str(), 
                                                       alphabet.c_str(), 
                                                       alphabet_length);
                                                       
    unsigned long long end_variant_id = get_variant_id(end_passphrase.c_str(), 
                                                     alphabet.c_str(), 
                                                     alphabet_length);
                                                     
    printf("Starting variant generation from ID %llu to %llu\n", start_variant_id, end_variant_id);
    printf("Including all lengths from %zu to %zu\n", 
           start_passphrase.length(), 
           end_passphrase.length());
    
    // Copy alphabet and its length to constant memory
    cudaMemcpyToSymbol(d_alphabet, alphabet.c_str(), alphabet_length + 1);
    cudaMemcpyToSymbol(d_alphabet_length, &alphabet_length, sizeof(int));

    // Copy p_chain_export to constant memory
    int p_chain_export = config["p_chain_export"].get<int>();
    cudaMemcpyToSymbol(d_p_chain_export, &p_chain_export, sizeof(int));
    
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
    
    // Read export configuration
    bool export_results = config["p_chain_export"].get<int>() == 1;
    
    if (export_results) {
        std::cout << "P-Chain address export enabled" << std::endl;
    }

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

    std::string uuid = generate_uuid();

    // Check if address was found
    cudaMemcpyFromSymbol(&h_address_found, d_address_found, sizeof(bool));
    if (h_address_found) {
        cudaMemcpyFromSymbol(h_address_value, d_address_value, P_CHAIN_ADDRESS_LENGTH + 1);
        printf("\nAddress found: %s\n", h_address_value);
        cudaMemcpyFromSymbol(h_passphrase_value, d_passphrase_value, MAX_PASSPHRASE_LENGTH);
        printf("Passphrase: %s\n", h_passphrase_value);

        // Save results to file with UUID
        std::string result_filename = "./results/result_" + uuid + ".txt";
        std::ofstream result_file(result_filename);
        if (result_file.is_open()) {
            result_file << "Address: " << h_address_value << std::endl;
            result_file << "Passphrase: " << h_passphrase_value << std::endl;
            result_file.close();
            std::cout << "Results saved to " << result_filename << std::endl;
        } else {
            std::cerr << "Unable to open " << result_filename << " for writing" << std::endl;
        }
    } else {
        printf("\nAddress not found\n");
    }

    // After kernel execution, export results if enabled
    if (export_results) {
        // Host-side array to store results
        ResultEntry* h_results = new ResultEntry[MAX_RESULTS];
        int h_result_count;
        
        // Copy results from device
        cudaMemcpyFromSymbol(&h_result_count, d_result_count, sizeof(int));
        cudaMemcpyFromSymbol(h_results, d_results, sizeof(ResultEntry) * min(h_result_count, MAX_RESULTS));
        
        // Export to TSV
        std::string export_filename = "./results/p_chain_addresses_" + uuid + ".tsv";
        std::ofstream export_file(export_filename);
        if (export_file.is_open()) {
            export_file << "GlobalIdx\tVariantId\tPassphrase\tAddress\n";
            for (int i = 0; i < min(h_result_count, MAX_RESULTS); i++) {
                export_file << h_results[i].globalIdx << "\t"
                          << h_results[i].variant_id << "\t"
                          << h_results[i].passphrase << "\t"
                          << h_results[i].address << "\n";
            }
            export_file.close();
            std::cout << "Exported " << min(h_result_count, MAX_RESULTS) 
                     << " P-Chain addresses to " << export_filename << std::endl;
            if (h_result_count > MAX_RESULTS) {
                std::cout << "Warning: " << h_result_count - MAX_RESULTS 
                         << " results were truncated due to buffer size" << std::endl;
            }
        } else {
            std::cerr << "Unable to open " << export_filename << " for writing" << std::endl;
        }
        
        delete[] h_results;
    }

    // Clean up
    cudaFree(d_mnemonic);
    cudaFree(d_start_passphrase);
    cudaFree(d_end_passphrase);
    cudaFree(d_expected_p_chain_address);
    cudaDeviceReset();

    return 0;
}