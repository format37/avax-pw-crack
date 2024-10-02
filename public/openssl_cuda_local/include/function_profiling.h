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