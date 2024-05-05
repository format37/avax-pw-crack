#include <gmp.h>
#include <stdlib.h>
#include <stdio.h>

// Point structure
typedef struct {
  mpz_t x;
  mpz_t y;
} Point;

// Compress public key  
char* compress_public_key(Point public_key) {

  mpz_t mod_result;
  mpz_init(mod_result);

  // Calculate public_key.y % 2
  mpz_mod_ui(mod_result, public_key.y, 2);
  // char prefix = (mpz_cmp_ui(mod_result, 0) == 0) ? '0' : '1';
  char prefix = (mpz_cmp_ui(mod_result, 0) == 0) ? '02' : '03';

  // Convert x coordinate to hexadecimal string
  char *x_str = mpz_get_str(NULL, 16, public_key.x);

  // Make sure it's 64 characters long, zero-padded if necessary
  char padded_x_str[65];
  snprintf(padded_x_str, sizeof(padded_x_str), "%064s", x_str);

  // Concatenate the prefix and the x coordinate
  char *compressed = malloc(65 + 1);  // 65 for the key and 1 for null-terminator
  sprintf(compressed, "%c%s", prefix, padded_x_str);

  // Clean up
  mpz_clear(mod_result);
  free(x_str);

  return compressed;
}

int main() {
    Point public_key;
    mpz_init_set_str(public_key.x, "66c1981565aedcc419cc56e72954e62fa0c3f43955b99a6a835afa2f29a7a7b6", 16);
    mpz_init_set_str(public_key.y, "49f4aa5706a41b7f0f26cb03375787701556e5f3b9d7f6dd53befd80dcfecd8f", 16);
    
    // Compress public key
    char* compressed = compress_public_key(public_key);  // Make sure to adapt this function to use GMP as well
    printf("Compressed public key: %s\n", compressed);

    return 0;
}
