#include <stdbool.h>
#include "cryptoutils.h"

void print_help(char *program_name) {
    printf("XOR Cypher by Leonardo Militz\n\n");
    printf("Usage:\n\t%s PLAINTEXT KEY", program_name);
}

bool check_valid_hex(char *message) {
    char whitelist[16] = "0123456789abcdef";

    int i, j;
    for (i = 0; i < strlen(message); i++) {
        bool valid = false;
        for (j = 0; j < strlen(whitelist)-1; j++) {
            if (tolower(message[i]) == whitelist[j]) {
                valid = true;
                break;
            }
        }
        if (!valid)
            return false;
    }

    return true;
}

bool handle_args(int argc, char *argv[]) {
    if (argc == 3) {
        return true;
    }

    print_help(argv[0]);
    return false;
}

int main(int argc, char *argv[])  {
    if (!handle_args(argc, argv))
        return 1;
    
    char *plaintext_hex = argv[1];
    char *key_hex = argv[2];

    if (!check_valid_hex(plaintext_hex)) {
        printf("\nerror: Invalid PLAINTEXT. Only use hexadecimal characters.");
        return 1;
    }

    if (!check_valid_hex(key_hex)) {
        printf("\nerror: Invalid KEY. Only use hexadecimal characters.");
        return 1;
    }

    if (strlen(key_hex) != strlen(plaintext_hex)) {
        printf("\nerror: KEY value must have the same lenght as the PLAINTEXT.");
        return 1;
    }

    size_t length = strlen(plaintext_hex) / 2;
    
    uint8_t plaintext[length];
    uint8_t key[length];
    uint8_t ciphertext[length];
    char ciphertext_hex[2 * length + 1];

    hex_to_bytes(plaintext_hex, plaintext, length);
    hex_to_bytes(key_hex, key, length);
    
    xor_cipher(plaintext, key, ciphertext, length);
    
    bytes_to_hex(ciphertext, ciphertext_hex, length);
    ciphertext_hex[2 * length] = '\0'; 
    
    printf("\nCiphertext:\t%s\n", ciphertext_hex);
    printf("Base64:\t\t%s\n", hex_to_base64(ciphertext_hex));

    return 0;
}