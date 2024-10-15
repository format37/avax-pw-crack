#include <cstdio>
#include <cstring>
#include "fixnum/warp_fixnum.cu"
#include "array/fixnum_array.h"

using namespace cuFIXNUM;

typedef warp_fixnum<64, u64_fixnum> fixnum;
typedef fixnum_array<fixnum> fixnum_array_t;

// This is our mock big number addition function
__device__ void bn_add(fixnum *result, fixnum *a, fixnum *b) {
    fixnum::add(*result, *a, *b);
}

// Kernel function to perform the addition
__global__ void add_kernel(fixnum *result, fixnum *a, fixnum *b) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < fixnum::SLOT_WIDTH) {
        bn_add(&result[idx], &a[idx], &b[idx]);
    }
}

void initialize_number(uint8_t* num, int size, const char* hex_string) {
    memset(num, 0, size);
    int len = strlen(hex_string);
    for (int i = 0; i < len; i += 2) {
        int value;
        sscanf(hex_string + len - i - 2, "%2x", &value);
        num[i / 2] = value;
    }
}

void print_number(const char* label, const uint8_t* num, int size) {
    printf("%s", label);
    for (int i = size - 1; i >= 0; --i) {
        printf("%02x", num[i]);
    }
    printf("\n");
}

int main() {
    uint8_t num1[64];
    uint8_t num2[64];

    // Initialize num1 to max 512-bit number minus 2
    initialize_number(num1, sizeof(num1), "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd");

    // Initialize num2 to 1
    memset(num2, 0, sizeof(num2));
    num2[0] = 0x01;

    fixnum_array_t *a = fixnum_array_t::create(num1, sizeof(num1), sizeof(num1));
    fixnum_array_t *b = fixnum_array_t::create(num2, sizeof(num2), sizeof(num2));
    fixnum_array_t *result = fixnum_array_t::create(1);

    // Launch the kernel
    add_kernel<<<1, fixnum::SLOT_WIDTH>>>((fixnum*)result->get_ptr(), (fixnum*)a->get_ptr(), (fixnum*)b->get_ptr());

    // Wait for GPU to finish
    cudaDeviceSynchronize();

    uint8_t output[64];
    int nelts;
    result->retrieve_all(output, sizeof(output), &nelts);

    print_number("a: ", num1, sizeof(num1));
    print_number("b: ", num2, sizeof(num2));
    print_number("Result: ", output, sizeof(output));

    delete a;
    delete b;
    delete result;

    return 0;
}