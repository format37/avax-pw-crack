#include <stdio.h>
#include <stdlib.h>
#include <cuda_runtime.h>

// Include your CUDA header files here
#include "bignum.h"
#include "point.h"
#include "public_key.h"

#define MAX_LINE_LENGTH 1024
#define MAX_TEST_CASES 1000
#define HEX_STRING_LENGTH 65  // 64 characters for 256-bit number + null terminator

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
__device__ void initBignumFromHex_err(BIGNUM *bn, const char *hex) {
    init_zero(bn);
    int len = d_strlen(hex);
    for (int i = 0; i < len; i += 16) {
        char chunk[17] = {0};
        int chunk_len = (len - i < 16) ? (len - i) : 16;
        d_strncpy(chunk, hex + len - i - chunk_len, chunk_len);
        BN_ULONG word = d_strtoull(chunk, NULL, 16);
        bn->d[bn->top++] = word;
    }
    bn->top = find_top(bn);
}

__device__ void initBignumFromHex(BIGNUM *bn, const char *hex) {
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

    bn->top = find_top(bn);
}

// CUDA kernel to perform the tests
__global__ void testEllipticCurve(TestCase *cases, int numCases) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= numCases) return;

    TestCase *tc = &cases[idx];
    EC_POINT_CUDA P, Q, resultAdd, resultDouble;

    // Initialize points P and Q
    initBignumFromHex(&P.x, tc->Px);
    initBignumFromHex(&P.y, tc->Py);
    initBignumFromHex(&Q.x, tc->Qx);
    initBignumFromHex(&Q.y, tc->Qy);

    // Perform point addition
    const BIGNUM CURVE_A_LOCAL = {0};
    const BIGNUM CURVE_P_LOCAL = {
        {
            0xFFFFFFFEFFFFFC2F,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF
        },
        CURVE_P_VALUES_MAX_SIZE,
        false
    };

    point_add(&resultAdd, &P, &Q, &CURVE_P_LOCAL, &CURVE_A_LOCAL);
    // Perform point doubling
    point_add(&resultDouble, &P, &P, &CURVE_P_LOCAL, &CURVE_A_LOCAL);
    // Initialize expected results
    BIGNUM expectedAddX, expectedAddY, expectedDoubleX, expectedDoubleY;
    initBignumFromHex(&expectedAddX, tc->ExpectedAddX);
    initBignumFromHex(&expectedAddY, tc->ExpectedAddY);
    initBignumFromHex(&expectedDoubleX, tc->ExpectedDoubleX);
    initBignumFromHex(&expectedDoubleY, tc->ExpectedDoubleY);

    // Compare results
    bool additionCorrect = (bn_cmp(&resultAdd.x, &expectedAddX) == 0) &&
                           (bn_cmp(&resultAdd.y, &expectedAddY) == 0);
    bool doublingCorrect = (bn_cmp(&resultDouble.x, &expectedDoubleX) == 0) &&
                           (bn_cmp(&resultDouble.y, &expectedDoubleY) == 0);

    // Print results
    printf("Test case %d: Addition %s, Doubling %s\n", idx,
           additionCorrect ? "PASS" : "FAIL",
           doublingCorrect ? "PASS" : "FAIL");
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
    numCases = readTestCases("../../../point_add_cases_full.txt", h_cases);
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
    int blocksPerGrid = (numCases + threadsPerBlock - 1) / threadsPerBlock;
    printf("Launching kernel with %d blocks of %d threads\n", blocksPerGrid, threadsPerBlock);
    testEllipticCurve<<<blocksPerGrid, threadsPerBlock>>>(d_cases, numCases);

    // Wait for GPU to finish
    cudaDeviceSynchronize();

    printf("Done\n");

    // Free device memory
    cudaFree(d_cases);
    
    // Free host memory
    free(h_cases);

    return 0;
}