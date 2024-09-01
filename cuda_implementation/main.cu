#include <cuda_runtime.h>
#include <fstream>
#include <iomanip>
#include <stdio.h>
#include <cuda.h>
#include "bignum.h"
#include "p_chain.h"

__global__ void restore_p_chain_example() {
    int thread_id = blockIdx.x * blockDim.x + threadIdx.x;
    uint8_t *mnemonic = (unsigned char *)"sell stereo useless course suffer tribe jazz monster fresh excess wire again father film sudden pelican always room attack rubber pelican trash alone cancel";
    const char *passphrase = "a";
    P_CHAIN_ADDRESS_STRUCT p_chain_address = restore_p_chain_address(mnemonic, passphrase);
    printf("[%d] Restored P-chain address: %s\n", thread_id, p_chain_address.data);
}

#define MAX_VARIANTS 32768
// #define MAX_VARIANTS 10
#define MAX_PASSPHRASE_LENGTH 10
#define P_CHAIN_ADDRESS_LENGTH 45  // Assuming the p-chain address is 45 characters long

__device__ const char alphabet[] = "abcdefghijklmnopqrstuvwxyz";
__device__ const int alphabet_length = 26;

__device__ unsigned char find_letter_variant(unsigned int variant_id, char* passphrase_value) {
    int result_length = 0;
    
    if (variant_id == 0) {
        passphrase_value[0] = alphabet[0];
        return 1;
    }
    
    while (variant_id > 0 && result_length < MAX_PASSPHRASE_LENGTH) {
        variant_id -= 1;  // Adjust for 0-based indexing
        passphrase_value[result_length++] = alphabet[variant_id % alphabet_length];
        variant_id /= alphabet_length;
    }
    
    // Reverse the result
    for (int i = 0; i < result_length / 2; i++) {
        char temp = passphrase_value[i];
        passphrase_value[i] = passphrase_value[result_length - 1 - i];
        passphrase_value[result_length - 1 - i] = temp;
    }
    
    return (unsigned char)result_length;
}

__global__ void variant_kernel(char* d_passphrases, unsigned char* d_lengths, char* d_p_chain_addresses) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    
    if (idx < MAX_VARIANTS) {
        char passphrase_value[MAX_PASSPHRASE_LENGTH] = {0};
        unsigned char passphrase_length;
        
        passphrase_length = find_letter_variant(idx, passphrase_value);
        
        // Copy passphrase to global memory
        for (int i = 0; i < passphrase_length; i++) {
            d_passphrases[idx * MAX_PASSPHRASE_LENGTH + i] = passphrase_value[i];
        }
        d_lengths[idx] = passphrase_length;
        // Set passphrase to "passphrase" for test purposes
        // char passphrase_value[MAX_PASSPHRASE_LENGTH] = "passphrase";
        // char passphrase_value[11] = "TESTPHRASE";
        
        // Calculate p-chain address
        uint8_t *mnemonic = (unsigned char *)"sell stereo useless course suffer tribe jazz monster fresh excess wire again father film sudden pelican always room attack rubber pelican trash alone cancel";
        // uint8_t *mnemonic = (unsigned char *)"sell stereo useless course suffer tribe jazz monster fresh excess wire again father film sudden pelican always room attack rubber pelican trash alone cancel";
        
        // uint8_t *passphrase_value = (unsigned char *)"mnemonicTESTPHRASE";

        // Print the mnemonic
        // printf("\n[%d]Mnemonic: [%s] ", idx, mnemonic);
        // printf("\n[%d]Mnemonic: ", idx);
        // print_as_hex(m_mnemonic, 156);

        // Print the passphrase
        // printf("\n[%d]Passphrase: [%s] ", idx, passphrase_value);
        /*
        // NOTE that we passed lengths in addition to values before. We may need to do the same here.
        compute_pbkdf2(
        (uint8_t *) m_mnemonic, 
        my_strlen((const char*) m_mnemonic), 
        (uint8_t *) salt, 
        my_strlen((const char*) salt),
	    2048, 
        64,
        bip39seed
        );*/

        // P_CHAIN_ADDRESS_STRUCT p_chain_address = restore_p_chain_address((uint8_t *) mnemonic, (uint8_t *) passphrase_value);
        P_CHAIN_ADDRESS_STRUCT p_chain_address = restore_p_chain_address(mnemonic, passphrase_value);
        // printf(" [%s]", p_chain_address.data);
        
        // Copy p-chain address to global memory
        for (int i = 0; i < P_CHAIN_ADDRESS_LENGTH; i++) {
            d_p_chain_addresses[idx * P_CHAIN_ADDRESS_LENGTH + i] = p_chain_address.data[i];
        }
    }
    __syncthreads();
}

void write_to_csv(const char* filename, char* passphrases, unsigned char* lengths, char* p_chain_addresses, int num_variants) {
    FILE* file = fopen(filename, "w");
    if (file == NULL) {
        printf("Error opening file!\n");
        return;
    }
    
    fprintf(file, "id,variant,p_chain_address\n");  // Updated CSV header
    
    for (int i = 0; i < num_variants; i++) {
        fprintf(file, "%d,", i);
        for (int j = 0; j < lengths[i]; j++) {
            fprintf(file, "%c", passphrases[i * MAX_PASSPHRASE_LENGTH + j]);
        }
        fprintf(file, ",");
        for (int j = 0; j < P_CHAIN_ADDRESS_LENGTH; j++) {
            fprintf(file, "%c", p_chain_addresses[i * P_CHAIN_ADDRESS_LENGTH + j]);
        }
        fprintf(file, "\n");
    }
    
    fclose(file);
}

int main() {
    const int THREADS_PER_BLOCK = 256;
    // const int THREADS_PER_BLOCK = 1;
    
    char* h_passphrases = (char*)malloc(MAX_VARIANTS * MAX_PASSPHRASE_LENGTH * sizeof(char));
    unsigned char* h_lengths = (unsigned char*)malloc(MAX_VARIANTS * sizeof(unsigned char));
    char* h_p_chain_addresses = (char*)malloc(MAX_VARIANTS * P_CHAIN_ADDRESS_LENGTH * sizeof(char));
    
    char* d_passphrases;
    unsigned char* d_lengths;
    char* d_p_chain_addresses;
    
    cudaMalloc(&d_passphrases, MAX_VARIANTS * MAX_PASSPHRASE_LENGTH * sizeof(char));
    cudaMalloc(&d_lengths, MAX_VARIANTS * sizeof(unsigned char));
    cudaMalloc(&d_p_chain_addresses, MAX_VARIANTS * P_CHAIN_ADDRESS_LENGTH * sizeof(char));
    
    int num_blocks = (MAX_VARIANTS + THREADS_PER_BLOCK - 1) / THREADS_PER_BLOCK;
    
    variant_kernel<<<num_blocks, THREADS_PER_BLOCK>>>(d_passphrases, d_lengths, d_p_chain_addresses);
    
    cudaMemcpy(h_passphrases, d_passphrases, MAX_VARIANTS * MAX_PASSPHRASE_LENGTH * sizeof(char), cudaMemcpyDeviceToHost);
    cudaMemcpy(h_lengths, d_lengths, MAX_VARIANTS * sizeof(unsigned char), cudaMemcpyDeviceToHost);
    cudaMemcpy(h_p_chain_addresses, d_p_chain_addresses, MAX_VARIANTS * P_CHAIN_ADDRESS_LENGTH * sizeof(char), cudaMemcpyDeviceToHost);
    
    write_to_csv("cuda_with_pchain.csv", h_passphrases, h_lengths, h_p_chain_addresses, MAX_VARIANTS);
    
    printf("CSV file 'cuda_with_pchain.csv' has been created with %d variants and their p-chain addresses.\n", MAX_VARIANTS);
    
    // Clean up
    free(h_passphrases);
    free(h_lengths);
    free(h_p_chain_addresses);
    cudaFree(d_passphrases);
    cudaFree(d_lengths);
    cudaFree(d_p_chain_addresses);
    
    // Check for errors
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("Error: %s\n", cudaGetErrorString(err));
        return -1;
    }

    cudaDeviceSynchronize();
    cudaDeviceReset();
    return 0;
}