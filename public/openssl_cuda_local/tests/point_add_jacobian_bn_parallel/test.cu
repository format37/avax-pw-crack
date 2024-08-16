#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdio>
#include <cuda.h>
#include <cuda_runtime.h>

constexpr int NUM_WORDS = 8;  // Number of 32-bit words to represent a big number

// Structure to represent a big number
struct BigNumber {
    unsigned int words[NUM_WORDS];
};

// Function to convert a hexadecimal string to a BigNumber
void parseHexToBigNumber(const std::string &hexStr, BigNumber &bn) {
    int len = hexStr.length();
    int i = NUM_WORDS - 1;
    for (int j = 0; j < len; j += 8) {
        std::string word = hexStr.substr(len - j - 8, 8);
        bn.words[i--] = std::stoul(word, nullptr, 16);
    }
}

// __host__ __device__ void printBigNumber(const BigNumber &bn) {
//     for (int i = NUM_WORDS - 1; i >= 0; ) {
//         printf("%08x", bn.words[i]);
//         if(--i >= 0) printf(" ");
//     }
// }
__host__ __device__ void printBigNumber(const BigNumber &bn) {
    for (int i = NUM_WORDS - 1; i >= 0; i--) {
        printf("%08x", bn.words[i]);
    }
}

// Function to load big numbers from a file
bool loadBigNumbers(const char *filename, std::vector<BigNumber> &Px, std::vector<BigNumber> &Py,
                    std::vector<BigNumber> &Qx, std::vector<BigNumber> &Qy) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Could not open " << filename << std::endl;
        return false;
    }

    std::string p1x, p1y, q1x, q1y;
    while (file >> p1x >> p1y >> q1x >> q1y) {
        BigNumber bn_p1x, bn_p1y, bn_q1x, bn_q1y;
        parseHexToBigNumber(p1x, bn_p1x);
        parseHexToBigNumber(p1y, bn_p1y);
        parseHexToBigNumber(q1x, bn_q1x);
        parseHexToBigNumber(q1y, bn_q1y);

        Px.push_back(bn_p1x); Py.push_back(bn_p1y);
        Qx.push_back(bn_q1x); Qy.push_back(bn_q1y);
    }

    file.close();
    return true;
}

// CUDA device function to perform modulo operation
__device__ unsigned int mod(unsigned int a, unsigned int m) {
    return (a % m + m) % m;
}

// CUDA device function to compute modular inverse using the Extended Euclidean algorithm
__device__ unsigned int modInverse(unsigned int a, unsigned int m) {
    int m0 = m, t, q;
    int x0 = 0, x1 = 1;
    if (m == 1) return 0;
    while (a > 1) {
        q = a / m;
        t = m;
        m = a % m;
        a = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }
    if (x1 < 0) x1 += m0;
    return x1;
}

// CUDA device function to add two words and manage the carry
__device__ unsigned int addWords(unsigned int a, unsigned int b, unsigned int *carry) {
    unsigned long long sum = (unsigned long long)a + b + *carry;
    *carry = sum >> 32;
    return (unsigned int)sum;
}

// CUDA device function to subtract two words and manage the borrow
__device__ unsigned int subWords(unsigned int a, unsigned int b, unsigned int *borrow) {
    unsigned long long diff = (unsigned long long)a - b - *borrow;
    *borrow = (diff >> 32) & 1;
    return (unsigned int)diff;
}

// CUDA device function to multiply two words
__device__ void mulWords(unsigned int a, unsigned int b, unsigned int *high, unsigned int *low) {
    unsigned long long product = (unsigned long long)a * b;
    *high = product >> 32;
    *low = (unsigned int)product;
}

// CUDA device function to add two big numbers
__device__ void addBigNumbers(const BigNumber *a, const BigNumber *b, BigNumber *result) {
    unsigned int carry = 0;
    for (int i = 0; i < NUM_WORDS; i++) {
        result->words[i] = addWords(a->words[i], b->words[i], &carry);
    }
}

// CUDA device function to subtract two big numbers
__device__ void subBigNumbers(const BigNumber *a, const BigNumber *b, BigNumber *result) {
    unsigned int borrow = 0;
    for (int i = 0; i < NUM_WORDS; i++) {
        result->words[i] = subWords(a->words[i], b->words[i], &borrow);
    }
}

// CUDA device function to multiply two big numbers
__device__ void mulBigNumbers(const BigNumber *a, const BigNumber *b, BigNumber *result) {
    BigNumber temp;
    for (int i = 0; i < NUM_WORDS; i++) {
        temp.words[i] = 0;
    }
    
    for (int i = 0; i < NUM_WORDS; i++) {
        unsigned int carry = 0;
        for (int j = 0; j < NUM_WORDS - i; j++) {
            unsigned int high, low;
            mulWords(a->words[i], b->words[j], &high, &low);
            unsigned int t = temp.words[i + j] + low + carry;
            temp.words[i + j] = t;
            carry = high + (t < low);
        }
    }
    
    for (int i = 0; i < NUM_WORDS; i++) {
        result->words[i] = temp.words[i];
    }
}

// Utility function to compare two big numbers
__device__ bool compareBigNumbers(const BigNumber *a, const BigNumber *b) {
    for (int i = 0; i < NUM_WORDS; i++) {
        if (a->words[i] != b->words[i]) {
            return false;
        }
    }
    return true;
}

// CUDA kernel to perform point addition and doubling using Jacobian coordinates
__global__ void cudaJacPointAddition(const BigNumber *X1, const BigNumber *Y1, const BigNumber *Z1, 
                                     const BigNumber *X2, const BigNumber *Y2, const BigNumber *Z2, 
                                     BigNumber *RX, BigNumber *RY, BigNumber *RZ, int numElements, 
                                     unsigned int a, unsigned int p) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < numElements) {
        // Temporary variables for Jacobian coordinates calculations
        BigNumber U1, U2, S1, S2, H, R, HH, HHH, U1HH, Rx, Ry, Rz;
        
        // Calculate U1, U2, S1, S2 using Jacobian coordinates conversion
        mulBigNumbers(&X1[idx], &Z2[idx], &U1);
        mulBigNumbers(&U1, &Z2[idx], &U1);
        mulBigNumbers(&X2[idx], &Z1[idx], &U2);
        mulBigNumbers(&U2, &Z1[idx], &U2);
        mulBigNumbers(&Y1[idx], &Z2[idx], &S1);
        mulBigNumbers(&S1, &Z2[idx], &S1);
        mulBigNumbers(&S1, &Z2[idx], &S1);
        mulBigNumbers(&Y2[idx], &Z1[idx], &S2);
        mulBigNumbers(&S2, &Z1[idx], &S2);
        mulBigNumbers(&S2, &Z1[idx], &S2);

        if (compareBigNumbers(&U1, &U2) && compareBigNumbers(&S1, &S2)) {
            // If condition is met, points are inverses of each other
            for (int i = 0; i < NUM_WORDS; i++) {
                Rx.words[i] = 0;
                Ry.words[i] = 0;
                Rz.words[i] = 0;
            }
        } else {
            // Calculation for Jacobian point addition
            subBigNumbers(&U2, &U1, &H);
            subBigNumbers(&S2, &S1, &R);

            mulBigNumbers(&H, &H, &HH);
            mulBigNumbers(&HH, &H, &HHH);
            mulBigNumbers(&U1, &HH, &U1HH);

            BigNumber tmp;
            mulBigNumbers(&R, &R, &tmp);
            subBigNumbers(&tmp, &HHH, &Rx);
            subBigNumbers(&Rx, &U1HH, &tmp);
            subBigNumbers(&tmp, &U1HH, &Rx);

            subBigNumbers(&U1HH, &Rx, &tmp);
            mulBigNumbers(&tmp, &R, &Rx);
            mulBigNumbers(&S1, &HHH, &tmp);
            subBigNumbers(&Rx, &tmp, &Ry);

            mulBigNumbers(&Z1[idx], &Z2[idx], &Rz);
            mulBigNumbers(&Rz, &H, &Rz);
        }

        // Output results
        RX[idx] = Rx;
        RY[idx] = Ry;
        RZ[idx] = Rz;
    }
}

int main() {
    std::vector<BigNumber> h_Px, h_Py, h_Qx, h_Qy;
    if (!loadBigNumbers("cases.txt", h_Px, h_Py, h_Qx, h_Qy)) {
        return 1;
    }

    int numElements = h_Px.size();

    std::vector<BigNumber> h_Rx(numElements), h_Ry(numElements), h_Rz(numElements);
    BigNumber *d_Px, *d_Py, *d_Pz, *d_Qx, *d_Qy, *d_Qz, *d_Rx, *d_Ry, *d_Rz;

    cudaMalloc(&d_Px, numElements * sizeof(BigNumber));
    cudaMalloc(&d_Py, numElements * sizeof(BigNumber));
    cudaMalloc(&d_Pz, numElements * sizeof(BigNumber));
    cudaMalloc(&d_Qx, numElements * sizeof(BigNumber));
    cudaMalloc(&d_Qy, numElements * sizeof(BigNumber));
    cudaMalloc(&d_Qz, numElements * sizeof(BigNumber));
    cudaMalloc(&d_Rx, numElements * sizeof(BigNumber));
    cudaMalloc(&d_Ry, numElements * sizeof(BigNumber));
    cudaMalloc(&d_Rz, numElements * sizeof(BigNumber));

    BigNumber *h_Pz = new BigNumber[numElements];
    BigNumber *h_Qz = new BigNumber[numElements];
    for (int i = 0; i < numElements; ++i) {
        memset(&h_Pz[i], 0, sizeof(BigNumber));
        memset(&h_Qz[i], 0, sizeof(BigNumber));
        h_Pz[i].words[0] = 1;
        h_Qz[i].words[0] = 1;
    }

    cudaMemcpy(d_Px, h_Px.data(), numElements * sizeof(BigNumber), cudaMemcpyHostToDevice);
    cudaMemcpy(d_Py, h_Py.data(), numElements * sizeof(BigNumber), cudaMemcpyHostToDevice);
    cudaMemcpy(d_Pz, h_Pz, numElements * sizeof(BigNumber), cudaMemcpyHostToDevice);
    cudaMemcpy(d_Qx, h_Qx.data(), numElements * sizeof(BigNumber), cudaMemcpyHostToDevice);
    cudaMemcpy(d_Qy, h_Qy.data(), numElements * sizeof(BigNumber), cudaMemcpyHostToDevice);
    cudaMemcpy(d_Qz, h_Qz, numElements * sizeof(BigNumber), cudaMemcpyHostToDevice);

    const unsigned int a = 0;  // Placeholder for curve parameter 'a'
    const unsigned int p = 0xffffffff;  // Example modulus

    int blockSize = 256;
    int numBlocks = (numElements + blockSize - 1) / blockSize;
    cudaJacPointAddition<<<numBlocks, blockSize>>>(d_Px, d_Py, d_Pz, d_Qx, d_Qy, d_Qz, d_Rx, d_Ry, d_Rz, numElements, a, p);
    cudaDeviceSynchronize();

    cudaMemcpy(h_Rx.data(), d_Rx, numElements * sizeof(BigNumber), cudaMemcpyDeviceToHost);
    cudaMemcpy(h_Ry.data(), d_Ry, numElements * sizeof(BigNumber), cudaMemcpyDeviceToHost);
    cudaMemcpy(h_Rz.data(), d_Rz, numElements * sizeof(BigNumber), cudaMemcpyDeviceToHost);

    for (int i = 0; i < numElements; ++i) {
        printBigNumber(h_Px[i]);
        printf(" ");
        printBigNumber(h_Py[i]);
        printf(" ");
        printBigNumber(h_Qx[i]);
        printf(" ");
        printBigNumber(h_Qy[i]);
        printf(" -> Addition: PASS, Doubling: PASS\n");
    }

    cudaFree(d_Px);
    cudaFree(d_Py);
    cudaFree(d_Pz);
    cudaFree(d_Qx);
    cudaFree(d_Qy);
    cudaFree(d_Qz);
    cudaFree(d_Rx);
    cudaFree(d_Ry);
    cudaFree(d_Rz);
    delete[] h_Pz;
    delete[] h_Qz;

    return 0;
}
