#include <iostream>
#include "cuda_interval_lib.h"

__global__ void division_example(interval_gpu<float> x, interval_gpu<float> y) {
    bool b;
    interval_gpu<float> result1 = division_part1(x, y, b);
    interval_gpu<float> result2 = division_part2(x, y, b);

    // Print the results
    printf("Division of [%f, %f] by [%f, %f]:\n", x.lower(), x.upper(), y.lower(), y.upper());
    printf("Part 1: [%f, %f]\n", result1.lower(), result1.upper());
    printf("Part 2: [%f, %f]\n", result2.lower(), result2.upper());
}

int main() {
    // Create intervals
    // interval_gpu<float> x(1.0f, 2.0f);
    // interval_gpu<float> y(-1.0f, 1.0f);
    // Create intervals representing the numbers 10 and 3
    interval_gpu<float> x(10.0f, 10.0f);
    interval_gpu<float> y(3.0f, 3.0f);

    // Launch the kernel
    division_example<<<1, 1>>>(x, y);

    // Synchronize for proper output
    cudaDeviceSynchronize();

    return 0;
}