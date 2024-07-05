#include "cryptoutils.h"

/* Função para contar o número de bits '1' em um byte. */
int count_bits(unsigned char byte) {
    int count = 0;
    while (byte) {
        count += byte & 1;
        byte >>= 1;
    }
    return count;
}

/* Função para o calculo da hamming distance. */
int hamming_distance(const unsigned char *str1, const unsigned char *str2, size_t len) {
    int distance = 0;
    size_t i;
    for (i = 0; i < len; ++i) {
        distance += count_bits(str1[i] ^ str2[i]);
    }
    return distance;
}

/* Função que realiza a operação XOR entre dois buffers */
void xor_cipher(const uint8_t* plaintext, const uint8_t* key, uint8_t* ciphertext, size_t length) {
    size_t i;
    for (i = 0; i < length; i++) {
        ciphertext[i] = plaintext[i] ^ key[i];
    }
}


/* Função auxiliar para converter um array de bytes para uma string Base64 */
char* base64_encode(const uint8_t* data, size_t input_length, size_t* output_length) {
    static const char encoding_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char *encoded_data;
    int mod_table[] = {0, 2, 1};

    *output_length = 4 * ((input_length + 2) / 3);

    encoded_data = (char *) malloc(*output_length + 1);
    if (encoded_data == NULL) return NULL;

    int i, j;
    for (i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? data[i++] : 0;
        uint32_t octet_b = i < input_length ? data[i++] : 0;
        uint32_t octet_c = i < input_length ? data[i++] : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        encoded_data[j++] = encoding_table[(triple >> 18) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 12) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 6) & 0x3F];
        encoded_data[j++] = encoding_table[triple & 0x3F];
    }

    for (i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    encoded_data[*output_length] = '\0';
    return encoded_data;
}

/* Função auxiliar para decodificar Base64 para um array de bytes */
uint8_t* base64_decode(const char* data, size_t input_length, size_t* output_length) {
    static const char decoding_table[] = {
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63, 
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 0, 64, 64, 
        64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64, 
        64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64
    };

    if (input_length % 4 != 0) return NULL;

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;

    uint8_t* decoded_data = (uint8_t*) malloc(*output_length);
    if (decoded_data == NULL) return NULL;

    int i, j;
    for (i = 0, j = 0; i < input_length;) {
        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[(int)data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[(int)data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[(int)data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[(int)data[i++]];

        uint32_t triple = (sextet_a << 18) | (sextet_b << 12) | (sextet_c << 6) | sextet_d;

        if (j < *output_length) decoded_data[j++] = (triple >> 16) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = triple & 0xFF;
    }

    return decoded_data;
}

/* Função auxiliar para converter uma string hexadecimal para um array de bytes */
void hex_to_bytes(const char* hex, uint8_t* bytes, size_t length) {
    size_t i;
    for (i = 0; i < length; i++) {
        sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
    }
}

/* Função auxiliar para converter um array de bytes para uma string hexadecimal */
void bytes_to_hex(const uint8_t* bytes, char* hex, size_t length) {
    size_t i;
    for (i = 0; i < length; i++) {
        sprintf(hex + 2 * i, "%02x", bytes[i]);
    }
}

/* Função para converter string hexadecimal para Base64 */
char* hex_to_base64(const char* hex) {
    size_t length = strlen(hex) / 2;
    size_t i;
    uint8_t* bytes = (uint8_t*) malloc(length);
    for (i = 0; i < length; i++) {
        sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
    }

    size_t output_length;
    char* base64 = base64_encode(bytes, length, &output_length);
    free(bytes);
    return base64;
}

/* Função para converter Base64 para hexadecimal */
char* base64_to_hex(const char* base64) {
    size_t input_length = strlen(base64);
    size_t output_length;
    uint8_t* bytes = base64_decode(base64, input_length, &output_length);

    if (bytes == NULL) return NULL;

    size_t i;
    char* hex = (char*) malloc(output_length * 2 + 1);
    for (i = 0; i < output_length; i++) {
        sprintf(hex + 2 * i, "%02x", bytes[i]);
    }

    free(bytes);
    return hex;
}

/* Função que realiza a operação XOR entre um buffer e uma chave de um único caractere */
void xor_single_key(const uint8_t* input, uint8_t key, uint8_t* output, size_t length) {
    size_t i;
    for (i = 0; i < length; i++) {
        output[i] = input[i] ^ key;
    }
}

bool is_character(char text) {
    if (isspace(text))
        return true;
    
    char* char_table = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890,.!?-";

    int i;
    for (i = 0; i < strlen(char_table); i++) {
        if (char_table[i] == text)
            return true;
    }

    return false;
}

/* Função para contar caracteres legíveis em um texto */
int count_readable_chars(const uint8_t* text, size_t length) {
    
    int count = 0;
    size_t i;
    for (i = 0; i < length; i++) {
       if (is_character(text[i]))
        count++;
    }
    return count;
}