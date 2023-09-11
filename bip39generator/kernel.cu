#include <cstdint>

__device__ unsigned int device_strlen(const char *str) {
    unsigned int len = 0;
    while (*str != '\0') {
        len++;
        str++;
    }
    return len;
}

__device__ void hash_function(const unsigned char *input, unsigned int len, unsigned char *output) {
    // Step 1: Preprocess the message
    // For simplicity, let's assume the input is always a multiple of 512 bits (64 bytes)
    // Normally you'd add padding as per the SHA-256 specification
    unsigned int num_blocks = len / 64;
    // uint32_t message[16 * num_blocks];
    uint32_t* message = (uint32_t*) malloc(16 * num_blocks * sizeof(uint32_t));
    if (message == NULL) {
        // handle error
        return;
    }
    
    for (int i = 0; i < len; i += 4) {
        message[i / 4] = (input[i] << 24) | (input[i + 1] << 16) | (input[i + 2] << 8) | (input[i + 3]);
    }

    // Step 2: Initialize hash values
    uint32_t h0 = 0x6a09e667;
    uint32_t h1 = 0xbb67ae85;
    uint32_t h2 = 0x3c6ef372;
    uint32_t h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f;
    uint32_t h5 = 0x9b05688c;
    uint32_t h6 = 0x1f83d9ab;
    uint32_t h7 = 0x5be0cd19;

    // Step 3: Main loop for processing each 512-bit block
    // For brevity, I'm omitting the actual loop and transformations.
    // You'd place your main_loop_sha256 logic here to update h0, h1, ..., h7
    // main_loop_sha256(message, &h0, &h1, &h2, &h3, &h4, &h5, &h6, &h7);
  
    // Step 4: Produce the final hash value (big-endian)
    // The hash is the concatenation of h0, h1, ..., h7
    // You'd typically use a loop or memcpy for this, but for brevity, we'll do it manually
    output[0] = h0 >> 24;
    output[1] = h0 >> 16;
    output[2] = h0 >> 8;
    output[3] = h0;
    output[4] = h1 >> 24;
    // ... (continue this pattern for h1 through h7)

    free(message);
}


__device__ void hmac(
    const unsigned char *key, 
    unsigned int key_len, 
    const unsigned char *message, 
    unsigned int message_len, 
    unsigned char *output
    ) {
    const unsigned int block_size = 64;  // Block size for the hash function (e.g., 64 bytes for SHA-256)
    unsigned char key_padded[block_size] = {0};
    unsigned char inner_padded[block_size];
    unsigned char outer_padded[block_size];
    unsigned char temp_hash[block_size];  // Temporary storage for hash

    // Step 1: Key padding
    if (key_len > block_size) {
        // Hash the key if it's longer than block_size
        hash_function(key, key_len, key_padded);
    } else {
        // Otherwise, just pad with zeros
        memcpy(key_padded, key, key_len);
    }

    // Step 2: Prepare inner and outer padded keys
    for (int i = 0; i < block_size; i++) {
        inner_padded[i] = key_padded[i] ^ 0x36;
        outer_padded[i] = key_padded[i] ^ 0x5c;
    }

    // Step 3: First hash calculation (inner hash)
    // Concatenating inner_padded and message. 
    // Note: For simplicity, assuming that (block_size + message_len) fits into the buffer
    memcpy(inner_padded + block_size, message, message_len);
    hash_function(inner_padded, block_size + message_len, temp_hash);

    // Step 4: Second hash calculation (outer hash)
    // Concatenating outer_padded and temp_hash
    // Note: For simplicity, assuming that (block_size + block_size) fits into the buffer
    memcpy(outer_padded + block_size, temp_hash, block_size);
    hash_function(outer_padded, 2 * block_size, output);
}

__device__ void pbkdf2_hmac( const unsigned char *hash_name, const unsigned char *salt, unsigned char *derived_key) {
    const uint32_t iterations = 2048;
    const uint32_t dklen = 32; // output key length in bytes
    const uint32_t hlen = 32;  // hash function output length in bytes
    const uint32_t slen = 16;  // assuming salt length is 16 bytes
    
    unsigned char T[hlen] = {0};
    unsigned char U[hlen] = {0};
    unsigned char salt_i[slen + 4] = {0};  // salt + 4-byte integer (i)
    // unsigned char hash_name_len = strlen((const char*)hash_name);  // Assuming hash_name is null-terminated
    unsigned int hash_name_len = device_strlen((const char*)hash_name);


    // Copy salt into salt_i
    memcpy(salt_i, salt, slen);

    // Step 1: Calculate PRF(salt, i) for i = 1, 2, ..., iterations
    for (uint32_t i = 1; i <= iterations; i++) {
        // Concatenate i to salt
        salt_i[slen] = (i >> 24) & 0xFF;
        salt_i[slen + 1] = (i >> 16) & 0xFF;
        salt_i[slen + 2] = (i >> 8) & 0xFF;
        salt_i[slen + 3] = i & 0xFF;

        // PRF(salt, i) - Compute HMAC
        // hmac(hash_name, salt, salt_i, T);
        hmac(hash_name, hash_name_len, salt_i, slen + 4, T);

        // Copy U to T for first iteration
        memcpy(T, U, hlen);

        // Subsequent iterations
        for (uint32_t j = 2; j <= iterations; ++j) {
            hmac(hash_name, hash_name_len, U, hlen, U);
            for (uint32_t k = 0; k < hlen; ++k) {
                T[k] ^= U[k];
            }
        }

        // Update derived_key with T
        for (uint32_t k = 0; k < hlen && (i - 1) * hlen + k < dklen; ++k) {
            derived_key[(i - 1) * hlen + k] ^= T[k];
        }
    }

    // Step 2: Compute the derived key
    // ...

    // Copy the derived key to the output buffer
    memcpy(derived_key, T, dklen);  // Note: This is just a placeholder. You would actually compute Z[] based on T[].
}


__global__ void Bip39SeedGenerator() {
    // Convert the mnemonic and passphrase to byte arrays (or use them as-is if you can)
    const unsigned char *m_mnemonic = (unsigned char *)"sell stereo useless course suffer tribe jazz monster fresh excess wire again father film sudden pelican always room attack rubber pelican trash alone cancel";
    unsigned char derived_key[64];  // This will hold the generated seed

    // Initialize derived_key to zeros
    for (int i = 0; i < 64; ++i) {
        derived_key[i] = 0;
    }

    // Preparing salt = "mnemonicTESTPHRASG"
    const unsigned char *salt = (unsigned char *)"mnemonicTESTPHRASG";

    // Call pbkdf2_hmac to perform the key derivation
    pbkdf2_hmac(m_mnemonic, salt, derived_key);
}
