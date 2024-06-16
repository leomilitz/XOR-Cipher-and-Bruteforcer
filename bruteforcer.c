#include "cryptoutils.h"

void print_help(char *program_name) {
    printf("XOR Cypher Bruteforcer by Leonardo Militz\n\n");
    printf("Usage:\n\t%s CIPHERTEXT", program_name);
}

bool check_valid_hex(char *message) {
    char whitelist[16] = "0123456789abcdef";

    int i, j;
    for (i = 0; i < strlen(message); i++) {
        bool valid = false;
        for (j = 0; j < strlen(whitelist); j++) {
            if (tolower(message[i]) == whitelist[j]) {
                valid = true;
                break;
            }
        }
        if (!valid) {
            printf("\nNot hexadecimal: %c", message[i]);
            return false;
        }
    }

    return true;
}

bool handle_args(int argc, char *argv[]) {
    if (argc == 2) {
        return true;
    }

    print_help(argv[0]);
    return false;
}

void xor_bruteforce(char* ciphertext_hex, uint8_t* ciphertext, size_t length) {
    uint8_t decoded[length];
    hex_to_bytes(ciphertext_hex, ciphertext, length);

    uint8_t best_key = 0;
    int best_score = 0;

    int key;
    for (key = 0; key <= 255; key++) {
        xor_single_key(ciphertext, key, decoded, length);
        
        int score = count_readable_chars(decoded, length);
        
        if (score > best_score) {
            best_score = score;
            best_key = key;
        }
    }

    xor_single_key(ciphertext, best_key, decoded, length);
    decoded[length] = '\0'; 

    printf("\nBest key: %c (0x%02x)\n", best_key, best_key);
    printf("Decoded message: %s\n", decoded);
}

int main(int argc, char *argv[])  {
    if (!handle_args(argc, argv))
        return 1;
    
    char *ciphertext_hex = argv[1];

    if (!check_valid_hex(ciphertext_hex)) {
        printf("\nerror: Invalid CIPHERTEXT. Only use hexadecimal characters.");
        return 1;
    }

    size_t length = strlen(ciphertext_hex) / 2;
    uint8_t ciphertext[length];

    xor_bruteforce(ciphertext_hex, ciphertext, length);

    return 0;
}