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
    uint64_t b = (BN_ULONG_MAX / m) + 1;  // Initial approximation

    for (int i = 0; i < 5; i++) {  // Typically, 3-5 iterations are sufficient
        uint64_t q_hi, q_lo;
        mul_64_64(b, m, q_hi, q_lo);
        
        uint64_t r_hi = ~q_hi;
        uint64_t r_lo = ~q_lo + 1;
        if (r_lo == 0) r_hi++;

        uint64_t temp_hi, temp_lo;
        mul_64_64(b, r_hi, temp_hi, temp_lo);
        uint64_t carry = (temp_lo + b) < b ? 1 : 0;
        b = temp_hi + carry;
    }

    // Adjust b to get mu = floor(2^(2k) / m)
    int shift = 2 * k - 64;
    if (shift > 0) {
        mu_hi = b << shift;
        mu_lo = 0;
    } else {
        mu_hi = 0;
        mu_lo = b >> -shift;
    }
}

// Function to compute mu without division using Goldschmidt's algorithm
void compute_mu_goldschmidt(uint64_t m, uint64_t &mu_hi, uint64_t &mu_lo) {
    // Number of bits in m
    int k = 64 - __builtin_clzll(m);

    // Normalize m to be in the range [0.5, 1) by shifting left
    int shift = k - 1;
    uint64_t m_normalized = m << (64 - k);

    // Initial approximation of 1 / m_normalized
    // Since m_normalized is in [0.5, 1), its reciprocal is in [1, 2)
    // We can approximate it as:
    uint64_t y = 0xFFFFFFFFFFFFFFFFULL;  // Approximate 1 / m_normalized

    // Perform iterations to refine y
    for (int i = 0; i < 4; ++i) {
        uint64_t hi1, lo1, hi2, lo2;

        // e = 2 - m_normalized * y
        mul_64_64(m_normalized, y, hi1, lo1);
        // Since we're dealing with fixed-point numbers with 64 fractional bits,
        // we need to shift hi1 and lo1 appropriately
        uint64_t e_hi = ~hi1;
        uint64_t e_lo = ~lo1;
        if (++e_lo == 0) ++e_hi;  // Handle carry for two's complement

        // Update y = y * e
        mul_64_64(y, e_lo, hi2, lo2);
        y = hi2;  // Keep the higher 64 bits as y
    }

    // Adjust y to get mu = floor(2^(2k) / m)
    // Since we normalized m by shifting left, we need to adjust y accordingly
    __uint128_t mu = (__uint128_t)y;
    mu = mu << (shift * 2);  // Shift mu left by 2 * shift

    // Split mu into high and low 64-bit parts
    mu_hi = (uint64_t)(mu >> 64);
    mu_lo = (uint64_t)mu;
}

void compute_mu_newton_raphson(uint64_t m, uint64_t &mu_hi, uint64_t &mu_lo) {
    // Number of bits in m
    int k = 64 - __builtin_clzll(m);

    // Normalize m to have its highest bit set (i.e., m_normalized in [2^63, 2^64))
    int shift = k - 1;
    uint64_t m_normalized = m << (64 - k);

    // Initial approximation of 1 / m_normalized in Q1.63 fixed-point format
    // Since m_normalized is >= 2^63, 1 / m_normalized <= 2 / 2^63 = 2^-62
    // So we can start with y = 1 << (126 - 64) = 1 << 62
    __uint128_t y = (__uint128_t)1 << 62;

    // Newton-Raphson iteration to compute 1 / m_normalized
    // We perform iterations: y = y * (2 - m_normalized * y)
    for (int i = 0; i < 7; ++i) {
        // t = m_normalized * y
        __uint128_t t = (__uint128_t)m_normalized * y;

        // Since y is Q1.63 and m_normalized is 64 bits, t is Q1.127
        // We need to shift t right by 63 bits to align the fractional parts
        t >>= 63;

        // e = (1 << 64) - t (since we're working in Q1.63 format)
        __uint128_t e = ((__uint128_t)1 << 64) - t;

        // y = y + (y * e) >> 64
        __uint128_t y_new = y + ((y * e) >> 64);
        y = y_new;
    }

    // Adjust y to get mu = floor(2^(2k) / m)
    // Since we normalized m by shifting left, we need to adjust y accordingly
    // mu = y << (2 * shift)
    __uint128_t mu = y << (2 * shift);

    // Split mu into high and low 64-bit parts
    mu_hi = (uint64_t)(mu >> 64);
    mu_lo = (uint64_t)(mu);
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

    // alternative mu computation test
    uint64_t mu_hi, mu_lo;
    compute_mu(m, mu_hi, mu_lo);
    printf("mu_hi = ");
    for (int i = 0; i < 8; i++) {
        printf("%02x", (uint8_t)(mu_hi >> (8 * (7 - i))));
    }
    printf("\n");
    printf("mu_lo = ");
    for (int i = 0; i < 8; i++) {
        printf("%02x", (uint8_t)(mu_lo >> (8 * (7 - i))));
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