#define PBKDF2_SHA256_IMPLEMENTATION
#include "pbkdf2_sha256.h"
#include <stdio.h>


void print_as_hex(const uint8_t *s,  const uint32_t slen)
{
	for (uint32_t i = 0; i < slen; i++)
	{
		printf("%02X%s", s[ i ], (i % 4 == 3) && (i != slen - 1) ? "-" : "");
	}
	printf("\n");
}

void compute_sha(const uint8_t *msg, uint32_t mlen)
{
	uint8_t md[SHA256_DIGESTLEN] = {0};  // Initialize to zero
    SHA256_CTX sha;
    sha256_init(&sha);

    sha256_update(&sha, msg, mlen);

    sha256_final(&sha, md);

    printf("Computed SHA-256: ");
    print_as_hex(md, sizeof md);
}

// Add a main function if not present elsewhere
int main() {
    const uint8_t message[] = "Hello, world!";
    compute_sha(message, sizeof(message) - 1);
    return 0;
}