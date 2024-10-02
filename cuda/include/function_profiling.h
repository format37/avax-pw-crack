#include <fstream>
#include <iostream>

#ifndef FUNCTION_PROFILING_H
#define FUNCTION_PROFILING_H

#define NUM_FUNCTIONS 7

typedef enum {
    FN_BN_MUL,
    FN_BN_MUL_FROM_DIV,
    FN_BN_ADD,
    FN_BN_SUB,
    FN_BN_SUB_FROM_DIV,
    FN_BN_DIV,
    FN_MAIN,
    FN_COUNT // Should be equal to NUM_FUNCTIONS
} FunctionIndex;

typedef struct {
    unsigned int function_calls[NUM_FUNCTIONS];
    unsigned long long function_times[NUM_FUNCTIONS];
} ThreadFunctionProfile;

#ifdef __CUDACC__
__device__ ThreadFunctionProfile *d_threadFunctionProfiles;
#else
extern __device__ ThreadFunctionProfile *d_threadFunctionProfiles;
#endif

#endif // FUNCTION_PROFILING_H

__device__ void record_function(FunctionIndex fn, unsigned long long start_time) {
    unsigned long long end_time = clock64();
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    ThreadFunctionProfile *threadProfile = &d_threadFunctionProfiles[idx];
    threadProfile->function_calls[fn]++;
    threadProfile->function_times[fn] += (end_time - start_time);
}

void write_function_profile_to_csv(const char* filename, ThreadFunctionProfile* profiles, int totalThreads, int threadsPerBlock) {
    const char* function_names_host[NUM_FUNCTIONS] = {
        "bn_mul",
        "bn_mul_from_div",
        "bn_add",
        "bn_sub",
        "bn_sub_from_div",
        "bn_div",
        "main"
    };
    
    std::ofstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Error opening file: " << filename << std::endl;
        return;
    }

    file << "BlockIdx,ThreadIdx,FunctionName,Calls,TotalTime(cycles)\n";

    for (int idx = 0; idx < totalThreads; idx++) {
        int blockIdx = idx / threadsPerBlock;
        int threadIdx = idx % threadsPerBlock;
        ThreadFunctionProfile &profile = profiles[idx];

        for (int fn = 0; fn < NUM_FUNCTIONS; fn++) {
            const char* functionName = function_names_host[fn];
            unsigned int calls = profile.function_calls[fn];
            unsigned long long totalTime = profile.function_times[fn];

            if (calls > 0) {
                file << blockIdx << "," << threadIdx << "," << functionName << "," << calls << "," << totalTime << "\n";
            }
        }
    }

    file.close();
    // std::cout << "Function profiling data saved to " << filename << std::endl;
}