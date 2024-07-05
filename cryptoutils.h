#ifndef  CRYPTOUTILS_H
#define  CRYPTOUTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <float.h>

/* XOR */
void xor_cipher(const uint8_t* plaintext, const uint8_t* key, uint8_t* ciphertext, size_t length);
void xor_single_key(const uint8_t* input, uint8_t key, uint8_t* output, size_t length);

/* Conversion */
void hex_to_bytes(const char* hex, uint8_t* bytes, size_t length);
void bytes_to_hex(const uint8_t* bytes, char* hex, size_t length);
char* hex_to_base64(const char* hex);
char* base64_to_hex(const char* base64);

/* Base64 */
char* base64_encode(const uint8_t* data, size_t input_length, size_t* output_length);
uint8_t* base64_decode(const char* data, size_t input_length, size_t* output_length);

/* Misc */
int count_readable_chars(const uint8_t* text, size_t length);
int hamming_distance(const unsigned char *str1, const unsigned char *str2, size_t len);

#endif /*CRYPTOUTILS_H*/