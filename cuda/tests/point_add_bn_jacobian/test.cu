#include <stdio.h>
#include <stdlib.h>
#include <cuda_runtime.h>

// Include your CUDA header files here
#include "bignum.h"
#include "point.h"
#include "public_key.h"

#define use_jacobian_coordinates
#define take_tests_from_host
#define NUM_TESTS 1

// The test cases have the following format:  
// Px Py Qx Qy (P+Q)x (P+Q)y (P+P)x (P+P)y  
// where P and Q are points on the elliptic curve. 

#define MAX_LINE_LENGTH 1024
#define MAX_TEST_CASES 1000
#define HEX_STRING_LENGTH 65  // 64 characters for 256-bit number + null terminator

#define cudaCheckError() { \
    cudaError_t e=cudaGetLastError(); \
    if(e!=cudaSuccess) { \
        printf("Cuda failure %s:%d: '%s'\n",__FILE__,__LINE__,cudaGetErrorString(e)); \
        exit(0); \
    } \
}

// Structure to hold a test case
typedef struct {
    char Px[HEX_STRING_LENGTH], Py[HEX_STRING_LENGTH], Qx[HEX_STRING_LENGTH], Qy[HEX_STRING_LENGTH];
    char ExpectedAddX[HEX_STRING_LENGTH], ExpectedAddY[HEX_STRING_LENGTH];
    char ExpectedDoubleX[HEX_STRING_LENGTH], ExpectedDoubleY[HEX_STRING_LENGTH];
} TestCase;

// Device function to calculate string length
__device__ int d_strlen(const char *str) {
    int len = 0;
    while (str[len] != '\0') {
        len++;
    }
    return len;
}

// Device function to copy n characters from src to dest
__device__ char* d_strncpy(char *dest, const char *src, int n) {
    int i;
    for (i = 0; i < n && src[i] != '\0'; i++) {
        dest[i] = src[i];
    }
    for (; i < n; i++) {
        dest[i] = '\0';
    }
    return dest;
}

// Device function to convert hex string to unsigned long long
__device__ unsigned long long d_strtoull(const char *str, char **endptr, int base) {
    unsigned long long result = 0;
    int i = 0;

    while (str[i] != '\0') {
        int digit;
        if (str[i] >= '0' && str[i] <= '9') {
            digit = str[i] - '0';
        } else if (str[i] >= 'a' && str[i] <= 'f') {
            digit = str[i] - 'a' + 10;
        } else if (str[i] >= 'A' && str[i] <= 'F') {
            digit = str[i] - 'A' + 10;
        } else {
            break;
        }
        
        if (digit >= base) {
            break;
        }
        
        result = result * base + digit;
        i++;
    }

    if (endptr) {
        *endptr = (char*)str + i;
    }

    return result;
}

// Function to initialize a BIGNUM from a hex string
__device__ void initBignumFromHex(BIGNUM_CUDA *bn, const char *hex) {
    init_zero(bn);
    int len = d_strlen(hex);
    int word_index = 0;

    for (int i = len; i > 0; i -= 16) {
        char chunk[17] = {0};
        int chunk_len = (i < 16) ? i : 16;
        d_strncpy(chunk, hex + i - chunk_len, chunk_len);
        BN_ULONG word = d_strtoull(chunk, NULL, 16);
        bn->d[word_index++] = word;
    }

    bn->top = find_top_cuda(bn);
}

// CUDA kernel to perform the tests
__global__ void testEllipticCurve(TestCase *cases, int numCases, ThreadFunctionProfile *d_threadFunctionProfiles_param) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= numCases) return;

    printf("\n[CUDA] Test case %d\n", idx);

    #ifdef function_profiler
        unsigned long long start_time = clock64();
        d_threadFunctionProfiles = d_threadFunctionProfiles_param;
    #endif

    TestCase *tc = &cases[idx];
    EC_POINT_CUDA P, Q, resultAdd, resultDouble;

    init_point_at_infinity(&P);
    init_point_at_infinity(&Q);
    init_point_at_infinity(&resultAdd);
    init_point_at_infinity(&resultDouble);

    // Initialize points P and Q
    #ifdef take_tests_from_host
        initBignumFromHex(&P.x, tc->Px);
        initBignumFromHex(&P.y, tc->Py);
        initBignumFromHex(&Q.x, tc->Qx);
        initBignumFromHex(&Q.y, tc->Qy);
    #else
        // 12dcd8c4a394f8761af731d2d1eca6ada6d43e004395b41858aa6a195361271e        
        P.x.d[0] = 0x58aa6a195361271e;
        P.x.d[1] = 0xa6d43e004395b418;
        P.x.d[2] = 0x1af731d2d1eca6ad;
        P.x.d[3] = 0x12dcd8c4a394f876;
        P.x.top = 4;
        // ff50375bd72dd99e2dcb852f1e63e495c4e76c2cad5aa0913f5000481c59f8be
        P.y.d[0] = 0x3f5000481c59f8be;
        P.y.d[1] = 0xc4e76c2cad5aa091;
        P.y.d[2] = 0x2dcb852f1e63e495;
        P.y.d[3] = 0xff50375bd72dd99e;
        P.y.top = 4;
        // 138484aeb7e6916b5435a48448039d75e44e3aab4d764a94a3b8674b1e26299a
        Q.x.d[0] = 0xa3b8674b1e26299a;
        Q.x.d[1] = 0xe44e3aab4d764a94;
        Q.x.d[2] = 0x5435a48448039d75;
        Q.x.d[3] = 0x138484aeb7e6916b;
        Q.x.top = 4;
        // dca814a26dc66a532e1082cad171b7e680a52a8dbb3ba8e295d2c749d18255f3
        Q.y.d[0] = 0x95d2c749d18255f3;
        Q.y.d[1] = 0x80a52a8dbb3ba8e2;
        Q.y.d[2] = 0x2e1082cad171b7e6;
        Q.y.d[3] = 0xdca814a26dc66a53;
        Q.y.top = 4;
    #endif

    // Perform point addition
    const BIGNUM_CUDA CURVE_A_LOCAL = {0};
    const BIGNUM_CUDA CURVE_P_LOCAL = {
        {
            0xFFFFFFFEFFFFFC2F,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF
        },
        CURVE_P_VALUES_MAX_SIZE,
        false
    };

    #ifdef use_jacobian_coordinates
        // // Debug with local test case initialization ++
        // BIGNUM_CUDA test_values_px[NUM_TESTS];
        // BIGNUM_CUDA test_values_py[NUM_TESTS];
        // BIGNUM_CUDA test_values_qx[NUM_TESTS];
        // BIGNUM_CUDA test_values_qx[NUM_TESTS];
        // // Initialize test values
        // for (int i = 0; i < NUM_TESTS; i++) {
        //     init_zero(&test_values_a[i]);
        //     init_zero(&test_values_m[i]);
        // }
        // // Test case 0
        // test_values_px[0].top = 4;
        // // 12dcd8c4a394f8761af731d2d1eca6ada6d43e004395b41858aa6a195361271e
        // test_values_px[0].d[0] = 0x58aa6a195361271e;
        // test_values_px[0].d[1] = 0xa6d43e004395b418;
        // test_values_px[0].d[2] = 0x1af731d2d1eca6ad;
        // test_values_px[0].d[3] = 0x12dcd8c4a394f876
        
        // test_values_m[1].neg = false; test_values_m[1].top = 1;
        // test_values_m[1].d[0] = 0xFFFFFFFFFFFFFFFDULL; test_values_m[1].d[1] = 0;
        bn_print_no_fuse("# P.x", &P.x);
        bn_print_no_fuse("# P.y", &P.y);
        bn_print_no_fuse("# Q.x", &Q.x);
        bn_print_no_fuse("# Q.y", &Q.y);
        // Debug with local test case initialization --

        EC_POINT_JACOBIAN P_jacobian, Q_jacobian, resultAdd_jacobian, resultDouble_jacobian;
        printf("\ncalling affine_to_jacobian\n");
        affine_to_jacobian(&P, &P_jacobian);
        affine_to_jacobian(&Q, &Q_jacobian);
        printf("\ncalling point_add_jacobian\n");
        point_add_jacobian(&resultAdd_jacobian, &P_jacobian, &Q_jacobian, &CURVE_P_LOCAL, &CURVE_A_LOCAL);
        printf("\ncalling jacobian_to_affine\n");
        jacobian_to_affine(&resultAdd_jacobian, &resultAdd, &CURVE_P_LOCAL);
        printf("\ncalling point_double_jacobian\n");
        jacobian_point_double(&resultDouble_jacobian, &P_jacobian, &CURVE_P_LOCAL, &CURVE_A_LOCAL);
        jacobian_to_affine(&resultDouble_jacobian, &resultDouble, &CURVE_P_LOCAL);
    #else
        point_add(&resultAdd, &P, &Q, &CURVE_P_LOCAL, &CURVE_A_LOCAL);
        point_add(&resultDouble, &P, &P, &CURVE_P_LOCAL, &CURVE_A_LOCAL);
    #endif

    // Initialize expected results
    BIGNUM_CUDA expectedAddX, expectedAddY, expectedDoubleX, expectedDoubleY;
    initBignumFromHex(&expectedAddX, tc->ExpectedAddX);
    initBignumFromHex(&expectedAddY, tc->ExpectedAddY);
    initBignumFromHex(&expectedDoubleX, tc->ExpectedDoubleX);
    initBignumFromHex(&expectedDoubleY, tc->ExpectedDoubleY);

    // Print resultAdd.x and resultAdd.y
    bn_print_no_fuse("point_add << X: ", &resultAdd.x);
    bn_print_no_fuse("point_add << Y", &resultAdd.y);
    // Print expectedAddX and expectedAddY
    bn_print_no_fuse("expectedAddX", &expectedAddX);
    bn_print_no_fuse("expectedAddY", &expectedAddY);
    // Compare results
    bool additionCorrect = (bn_cmp(&resultAdd.x, &expectedAddX) == 0) &&
                           (bn_cmp(&resultAdd.y, &expectedAddY) == 0);

    // Print resultDouble.x and resultDouble.y
    bn_print_no_fuse("\npoint_double << X: ", &resultDouble.x);
    bn_print_no_fuse("point_double << Y: ", &resultDouble.y);
    // Print expectedDoubleX and expectedDoubleY
    bn_print_no_fuse("expectedDoubleX", &expectedDoubleX);
    bn_print_no_fuse("expectedDoubleY", &expectedDoubleY);
    // compare results
    bool doublingCorrect = (bn_cmp(&resultDouble.x, &expectedDoubleX) == 0) &&
                           (bn_cmp(&resultDouble.y, &expectedDoubleY) == 0);

    // Print results
    printf("\nAddition %s, Doubling %s\n",
           additionCorrect ? "PASS" : "FAIL",
           doublingCorrect ? "PASS" : "FAIL");
    #ifdef function_profiler
        record_function(FN_MAIN, start_time);
    #endif
}

// Host function to read test cases from file
int readTestCases(const char *filename, TestCase *cases) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Error opening file");
        return -1;
    }

    char line[MAX_LINE_LENGTH];
    int numCases = 0;

    while (fgets(line, sizeof(line), file) && numCases < MAX_TEST_CASES) {
        TestCase *tc = &cases[numCases];
        sscanf(line, "%64s %64s %64s %64s %64s %64s %64s %64s",
               tc->Px, tc->Py, tc->Qx, tc->Qy,
               tc->ExpectedAddX, tc->ExpectedAddY,
               tc->ExpectedDoubleX, tc->ExpectedDoubleY);
        numCases++;
    }

    fclose(file);
    return numCases;
}

int main() {
    TestCase *h_cases, *d_cases;
    int numCases;

    // Read test cases from file
    h_cases = (TestCase*)malloc(MAX_TEST_CASES * sizeof(TestCase));
    numCases = readTestCases("point_add_cases_full.txt", h_cases);
    if (numCases < 0) {
        fprintf(stderr, "Failed to read test cases\n");
        return 1;
    }

    // Allocate memory on device
    cudaMalloc(&d_cases, numCases * sizeof(TestCase));

    // Copy data to device
    cudaMemcpy(d_cases, h_cases, numCases * sizeof(TestCase), cudaMemcpyHostToDevice);

    // Launch kernel
    // int threadsPerBlock = 256;
    int threadsPerBlock = 1;
    // int blocksPerGrid = (numCases + threadsPerBlock - 1) / threadsPerBlock;
    int blocksPerGrid = 1;

    // Function profiling
    int totalThreads = blocksPerGrid * threadsPerBlock;
    // Allocate per-thread function profiling data
    ThreadFunctionProfile *h_threadFunctionProfiles = new ThreadFunctionProfile[totalThreads];
    ThreadFunctionProfile *d_threadFunctionProfiles;
    cudaMalloc(&d_threadFunctionProfiles, totalThreads * sizeof(ThreadFunctionProfile));
    cudaMemset(d_threadFunctionProfiles, 0, totalThreads * sizeof(ThreadFunctionProfile));

    printf("Launching kernel with %d blocks of %d threads\n", blocksPerGrid, threadsPerBlock);
    testEllipticCurve<<<blocksPerGrid, threadsPerBlock>>>(d_cases, numCases, d_threadFunctionProfiles);

    // cudaCheckError();

    // Wait for GPU to finish
    cudaDeviceSynchronize();

    // cudaCheckError();

    printf("Done\n");

    #ifdef function_profiler
        // After kernel execution, copy profiling data back to host
        cudaMemcpy(h_threadFunctionProfiles, d_threadFunctionProfiles, totalThreads * sizeof(ThreadFunctionProfile), cudaMemcpyDeviceToHost);
        // After kernel execution and copying profiling data back to host
        write_function_profile_to_csv("../../performance/functions_data/profile.csv", h_threadFunctionProfiles, totalThreads, threadsPerBlock);
    #endif
    // Clean up
    delete[] h_threadFunctionProfiles;
    cudaFree(d_threadFunctionProfiles);

    // Free device memory
    cudaFree(d_cases);

    // Free host memory
    free(h_cases);

    return 0;
}