#include <cstdio>
#include <cstring>
#include "fixnum/warp_fixnum.cu"
#include "array/fixnum_array.h"
#include "functions/quorem_preinv.cu"

using namespace cuFIXNUM;

typedef warp_fixnum<64, u64_fixnum> fixnum;
typedef fixnum_array<fixnum> fixnum_array_t;

// Functor to perform division with remainder on the device
template<typename fixnum>
struct divide_with_remainder_functor {
    __device__ void operator()(fixnum &quotient, fixnum &remainder, fixnum a, fixnum b) {
        quorem_preinv<fixnum> div_op(b);
        fixnum a_hi = fixnum::zero();
        div_op(quotient, remainder, a_hi, a);
    }
};

// Function to initialize a number from a hex string
void initialize_number(uint8_t* num, int size, const char* hex_string) {
    memset(num, 0, size);
    int len = strlen(hex_string);
    for (int i = 0; i < len; i += 2) {
        int value;
        sscanf(hex_string + len - i - 2, "%2x", &value);
        num[i / 2] = value;
    }
}

// Function to print a number
void print_number(const char* label, const uint8_t* num, int size) {
    printf("%s0x", label);
    for (int i = size - 1; i >= 0; --i) {
        printf("%02x", num[i]);
    }
    printf("\n");
}

int main() {
    uint8_t num1[64];
    uint8_t num2[64];

    // Initialize num1 and num2
    initialize_number(num1, sizeof(num1), "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe");
    initialize_number(num2, sizeof(num2), "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ff"); // Divisor = 255

    int nelts = 1; // Number of elements

    // Create fixnum arrays from the initialized numbers
    fixnum_array_t *a = fixnum_array_t::create(num1, sizeof(num1), nelts);
    fixnum_array_t *b = fixnum_array_t::create(num2, sizeof(num2), nelts);
    fixnum_array_t *quotient = fixnum_array_t::create(nelts);
    fixnum_array_t *remainder = fixnum_array_t::create(nelts);

    // Apply the division functor to the arrays
    fixnum_array_t::template map<divide_with_remainder_functor>(quotient, remainder, a, b);

    // Retrieve the quotient and remainder
    uint8_t quotient_output[64];
    uint8_t remainder_output[64];
    int nelts_out;
    quotient->retrieve_all(quotient_output, sizeof(quotient_output), &nelts_out);
    remainder->retrieve_all(remainder_output, sizeof(remainder_output), &nelts_out);

    // Print the input numbers, quotient, and remainder
    print_number("Dividend:  ", num1, sizeof(num1));
    print_number("Divisor:   ", num2, sizeof(num2));
    print_number("Quotient:  ", quotient_output, sizeof(quotient_output));
    print_number("Remainder: ", remainder_output, sizeof(remainder_output));

    // Clean up
    delete a;
    delete b;
    delete quotient;
    delete remainder;

    return 0;
}