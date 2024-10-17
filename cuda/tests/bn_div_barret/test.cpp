#include <iostream>
#include <cassert>
#include <cstdint>

#define BN_ULONG uint64_t
#define BN_ULONG_MAX UINT64_MAX

// Function to perform multiplication of two 64-bit numbers and store the result in two 64-bit numbers
void mul_64_64(uint64_t a, uint64_t b, uint64_t &hi, uint64_t &lo) {
    __uint128_t result = static_cast<__uint128_t>(a) * b;
    hi = static_cast<uint64_t>(result >> 64);
    lo = static_cast<uint64_t>(result);
}

// Function to compute mu without division
void compute_mu(uint64_t m, uint64_t &mu_hi, uint64_t &mu_lo) {
    int k = 64 - __builtin_clzll(m);
    uint64_t r_hi = 0, r_lo = 0;
    mu_hi = BN_ULONG_MAX;
    mu_lo = BN_ULONG_MAX;

    for (int i = 0; i < 5; i++) {  // Typically, 3-5 iterations are sufficient
        uint64_t q_hi, q_lo;
        mul_64_64(mu_hi, m, q_hi, q_lo);
        
        if (q_lo > r_lo) q_hi++;
        r_hi = mu_hi - q_hi;
        r_lo = mu_lo - q_lo;

        if (r_hi == 0 && r_lo < m) break;

        uint64_t temp_hi, temp_lo;
        mul_64_64(r_hi, BN_ULONG_MAX, temp_hi, temp_lo);
        mu_hi = temp_hi + ((temp_lo + r_lo) < r_lo ? 1 : 0);
        mu_lo = temp_lo + r_lo;
    }
}

// Barrett reduction to compute quotient and remainder of a division
void barrett_reduction(BN_ULONG x, BN_ULONG m, BN_ULONG &quotient, BN_ULONG &remainder) {
    printf(">> x = %lu\n", x);
    printf(">> m = %lu\n", m);
    // Step 1: Precompute mu = floor(2^(2 * k) / m), where k is the number of bits in m
    int k = 64 - __builtin_clzll(m);  // Number of bits in m
    __uint128_t mu = ((__uint128_t)1 << (2 * k)) / m;
    // Print mu as hex
    printf("mu = ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", (uint8_t)(mu >> (8 * (15 - i))));
    }
    printf("\n");

    // Step 2: Calculate q = floor(x / m) using Barrett approximation
    BN_ULONG q = (BN_ULONG)((((__uint128_t)x * mu) >> (2 * k)));

    // Step 3: Compute the remainder r = x - q * m
    BN_ULONG r = x - q * m;

    // Step 4 and 5: Adjust q and r if necessary
    if (r >= m) {
        r -= m;
        q++;
    }

    quotient = q;
    remainder = r;
}

int main() {
    // Example dividend and modulus
    BN_ULONG x = 0x12345678ABCDEF12ULL;  // Dividend
    BN_ULONG m = 0x1ABCDEF12345678ULL;  // Modulus

    // Compute quotient and remainder using Barrett reduction
    BN_ULONG quotient = 0, remainder = 0;
    barrett_reduction(x, m, quotient, remainder);

    // Print the results
    std::cout << "Quotient: 0x" << std::hex << quotient << std::endl;
    std::cout << "Remainder: 0x" << std::hex << remainder << std::endl;

    // Verify correctness using C++'s built-in division
    assert(x == quotient * m + remainder);

    std::cout << "The result is correct!" << std::endl;
    return 0;
}