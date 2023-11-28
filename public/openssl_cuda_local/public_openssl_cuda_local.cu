#include <stdio.h>
#include <string.h>
#include <cuda.h>
#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/obj_mac.h"
#include "bignum.h"
//#include "source/crypto/ec/ec_key.c"


__device__ void print_as_hex_char(unsigned char *data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

/*// Debug print for OpenSSL BIGNUM
void print_bn(const char* label, const BIGNUM* bn) {
	char* bn_str = BN_bn2dec(bn);
	printf("%s: %s\n", label, bn_str);
	OPENSSL_free(bn_str);
}*/

// Debug print for OpenSSL BIGNUM
__device__ void print_bn(const char* label, const BIGNUM* bn) {
    bn->d[0] = 0;
    printf("%s: ", label);
    for (int i = 0; i < bn->top; i++) {
        printf("%08lx", bn->d[i]);  // Use %08lx for 32-bit or %08llx for 64-bit unsigned long
    }
    printf("\n");
}

/*// Debug print for OpenSSL BIGNUM in Hexadecimal
void print_bn_hex(const char* label, const BIGNUM* bn) {
    char* bn_str = BN_bn2hex(bn);
    printf("%s (Hexadecimal): %s\n", label, bn_str);
    OPENSSL_free(bn_str);
}*/
// Debug print for OpenSSL BIGNUM in Hexadecimal
__device__ void print_bn_hex(const char* label, const BIGNUM* bn) {
    printf("%s (Hexadecimal): ", label);
    
    // The BIGNUM is usually stored in a little-endian format.
    // Print from the most significant part to the least significant.
    for (int i = bn->top - 1; i >= 0; i--) {
        // Use %08lx for 32-bit or %08llx for 64-bit unsigned long
        printf("%08lx", bn->d[i]);
    }
    
    printf("\n");
}

// Function to compress public key
__device__ void compress_pubkey(EC_KEY *key, unsigned char *compressed, size_t *compressed_len) {
    const EC_POINT *point = EC_KEY_get0_public_key(key);
    // const EC_GROUP *group = EC_KEY_get0_group(key);
    // *compressed_len = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, compressed, 65, NULL);
}

__global__ void testKernel() {

    printf("Hello from the kernel\n");    

}

int main() {
    // print that we starting
    printf("Starting\n");
    testKernel<<<1,1>>>();
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("Error: %s\n", cudaGetErrorString(err));
        return -1;
    }
    cudaDeviceSynchronize();
    return 0;
}