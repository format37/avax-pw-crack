#include <stdio.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>

// Function to compress public key
void compress_pubkey(EC_KEY *key, unsigned char *compressed, size_t *compressed_len) {
    const EC_POINT *point = EC_KEY_get0_public_key(key);
    const EC_GROUP *group = EC_KEY_get0_group(key);
    *compressed_len = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, compressed, 65, NULL);
}

int main() {
    EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
    BIGNUM *priv_key = BN_new();
    unsigned char compressed_pubkey[65];
    size_t compressed_pubkey_len;

    // Set private key
    BN_hex2bn(&priv_key, "2E09165B257A4C3E52C9F4FAA6322C66CEDE807B7D6B4EC3960820795EE5447F");
    EC_KEY_set_private_key(eckey, priv_key);

    // Generate public key
    EC_POINT *pub_key = EC_POINT_new(EC_KEY_get0_group(eckey));
    EC_POINT_mul(EC_KEY_get0_group(eckey), pub_key, priv_key, NULL, NULL, NULL);
    EC_KEY_set_public_key(eckey, pub_key);

    // Print uncompressed public key
    char *pub_key_hex = EC_POINT_point2hex(EC_KEY_get0_group(eckey), pub_key, POINT_CONVERSION_UNCOMPRESSED, NULL);
    printf("\nUncompressed Public Key: %s\n", pub_key_hex);
    OPENSSL_free(pub_key_hex);

    // Compress public key
    compress_pubkey(eckey, compressed_pubkey, &compressed_pubkey_len);

    // Print compressed public key
    printf("\nCompressed Public Key: ");
    for (size_t i = 0; i < compressed_pubkey_len; i++) {
        printf("%02x", compressed_pubkey[i]);
    }
    printf("\n");

    // Cleanup
    EC_POINT_free(pub_key);
    BN_free(priv_key);
    EC_KEY_free(eckey);

    return 0;
}
