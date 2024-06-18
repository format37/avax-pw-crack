#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BN_ULONG_NUM_BITS 64
// Number of hexadecimal symbols in a BN_ULONG value
// Each hexadecimal symbol represents 4 bits
#define BN_ULONG_NUM_SYMBOLS BN_ULONG_NUM_BITS/4
#define MAX_BIGNUM_SIZE 3
#define BN_ULONG unsigned long long

typedef struct bignum_st {
    BN_ULONG d[MAX_BIGNUM_SIZE];
    int top;
    int dmax;
    int neg;
    int flags;
} BIGNUM_CUDA;

void init_zero(BIGNUM_CUDA *bn, int capacity) {
    for (int i = 0; i < MAX_BIGNUM_SIZE; i++) {
        bn->d[i] = 0;
    }
    bn->top = 1;
    bn->neg = 0;
    bn->dmax = MAX_BIGNUM_SIZE - 1;
}

void bn_print_bn(const char* msg, BIGNUM_CUDA* a) {
    printf("%s", msg);
    if (a->neg) {
        printf("-");  // Handle the case where BIGNUM is negative
    }
    for (int i = MAX_BIGNUM_SIZE - 1; i >= 0; i--) {
        // print i
        printf(" (%d) ", i);
        // Print words up to top - 1 with appropriate formatting
        if (i == MAX_BIGNUM_SIZE - 1) {
            printf("%llx", a->d[i]);
        } else {
            printf(" %016llx", a->d[i]);
        }
    }
    printf("\n");
}

void f(BIGNUM_CUDA* words_original, int S, int N, BIGNUM_CUDA* result) {
    // Reverse words
    BIGNUM_CUDA words;
    for (int i = 0; i < MAX_BIGNUM_SIZE; i++) {
        words.d[i] = words_original->d[MAX_BIGNUM_SIZE - 1 - i];
    }
    // Concatenate all words together
    int full_length = MAX_BIGNUM_SIZE * BN_ULONG_NUM_SYMBOLS;
    char all_words[full_length + 1];
    all_words[0] = '\0';
    for (int i = 0; i < MAX_BIGNUM_SIZE; i++) {
        char word[BN_ULONG_NUM_SYMBOLS + 1];
        sprintf(word, "%016llx", words.d[i]);
        strcat(all_words, word);
    }

    // Get the start_symbol
    int start_symbol = full_length - S;
    // Get the final_symbol
    int final_symbol = full_length - N;
    // Get the substring from start_symbol to the final_symbol
    char substring[N - S + 1];
    strncpy(substring, all_words + final_symbol, start_symbol - final_symbol);
    substring[start_symbol - final_symbol] = '\0';

    // Get the length of the substring
    int substring_length = strlen(substring);
    // Calculate the padding
    int padding = full_length - substring_length;

    // Initialize the result to zero
    init_zero(result, MAX_BIGNUM_SIZE);

    // print substring for debugging
    printf("\nSubstring [%d, %d]: %s\n", S, N, substring);

    unsigned char substring_symbol_id = MAX_BIGNUM_SIZE * BN_ULONG_NUM_SYMBOLS - 1;
    // Define the mapping of the char symbol to the BN_ULONG symbol
    unsigned char char_values[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };
    BN_ULONG ulong_values[16] = {
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
        0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf
    };
    // Words: 298b56ae54fe2c3d e75656ab232452bf 0284619f7ea27d52
    // Substring: 4fe2c3d
    unsigned char revision = 1;
    if (revision == 1) {
        unsigned char word = 0;
        unsigned char shifting = 0;
        for (unsigned char i=0;i<substring_length;i++) {
            printf("substring[%d]: %c\n", substring_length-i-1, substring[substring_length-i-1]);
            // find the corresponding ulong value
            for (unsigned char j=0; j<16; j++) {
                if (substring[substring_length-i-1] == char_values[j]) {
                    if (shifting == 0) {
                        result->d[word] |= ulong_values[j];
                    } else {
                        result->d[word] |= ulong_values[j] << (shifting * 4);
                    }
                    shifting++;
                    break;
                }
            }
            if (shifting == 16) {
                shifting = 0;
                word++;
            }
        }
    }
    if (revision == 0) {
        unsigned char shifting = 0;
        for (unsigned char word=0; word<MAX_BIGNUM_SIZE; word++) { // 0,1,2
            for (unsigned char i=0; i<BN_ULONG_NUM_SYMBOLS; i++) { // 0,1,2, .. 15
                if (substring_symbol_id < substring_length) {
                    // print the current word
                    printf("word: %d ", word);
                    // print the current current_symbol_id
                    printf("substring_symbol_id: %d ", substring_symbol_id);
                    // print the current symbol of the substring
                    printf("substring[substring_symbol_id]: %c\n", substring[substring_symbol_id]);
                    // find the corresponding ulong value
                    for (unsigned char j=0; j<16; j++) {
                        if (substring[substring_symbol_id] == char_values[j]) {
                            if (shifting == 0) {
                                result->d[MAX_BIGNUM_SIZE-word-1] |= ulong_values[j];
                            } else {
                                result->d[MAX_BIGNUM_SIZE-word-1] |= ulong_values[j] << (shifting * 4);
                            }
                            shifting++;
                            // result->d[MAX_BIGNUM_SIZE-word-1] |= ulong_values[j] << (i * 4);
                            // result->d[word] |= ulong_values[j] << (i * 4);
                            break;
                        }
                    }
                }
                substring_symbol_id--;
            }
        }
    }
}

int main() {
    BIGNUM_CUDA words;
    init_zero(&words, MAX_BIGNUM_SIZE);
    words.d[0] = 0x0284619f7ea27d52;
    words.d[1] = 0xe75656ab232452bf;
    words.d[2] = 0x298b56ae54fe2c3d;

    printf("\nWords:\n");
    bn_print_bn("", &words);

    printf("\nTests:\n");
    BIGNUM_CUDA result;
    f(&words, 0, 7, &result);
    bn_print_bn("", &result);

    f(&words, 3, 20, &result);
    bn_print_bn("", &result);

    f(&words, 22, 45, &result);
    bn_print_bn("", &result);

    return 0;
}