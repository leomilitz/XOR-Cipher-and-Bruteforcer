#include "cryptoutils.h"

#define MAX_KEYSIZE 40
#define MIN_KEYSIZE 2

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

/* Função para transpor blocos de tamanho keysize */
void transpose_blocks(uint8_t *ciphertext, char **blocks, size_t len, int keysize) {
    int i, j;
    for (i = 0; i < keysize; ++i) {
        blocks[i] = malloc((len / keysize) + 1);
        int index = 0;
        for (j = i; j < len; j += keysize) {
            blocks[i][index++] = ciphertext[j];
        }
    }
}

/* Função para encontrar o keysize */
double find_probable_keysize(uint8_t *ciphertext, size_t len) {
    double min_avg_distance = DBL_MAX;
    int probable_keysize = 0, keysize, i;

    for (keysize = MIN_KEYSIZE; keysize <= MAX_KEYSIZE; ++keysize) {
        double total_distance = 0;
        int num_blocks = len / keysize;
        for (i = 0; i < num_blocks - 1; ++i) {
            int distance = hamming_distance(ciphertext + i * keysize, ciphertext + (i + 1) * keysize, keysize);
            total_distance += (double)distance / keysize;
        }

        double avg_distance = total_distance / (num_blocks - 1);

        if (avg_distance < min_avg_distance) {
            min_avg_distance = avg_distance;
            probable_keysize = keysize;
        }
    }

    return probable_keysize;
}

/* Função para calcular a frequência dos caracteres em um buffer */
void calc_freq(unsigned char *buf, size_t len, double *freq) {
    size_t i;
    for (i = 0; i < len; ++i) {
        if (isprint(buf[i])) {
            freq[buf[i]] += 1;
        }
    }
    for (i = 0; i < 256; ++i) {
        freq[i] /= len;
    }
}

/* Função para determinar a chave XOR de um único caractere */
char xor_bruteforce_single_key(char *ciphertext, size_t len) {
    double english_freq[256] = {0};
    /* Frequências aproximadas dos caracteres na língua inglesa */
    english_freq['a'] = 0.065;
    english_freq['b'] = 0.012;
    english_freq['c'] = 0.022;
    english_freq['d'] = 0.033;
    english_freq['e'] = 0.103;
    english_freq['f'] = 0.020;
    english_freq['g'] = 0.016;
    english_freq['h'] = 0.049;
    english_freq['i'] = 0.056;
    english_freq['j'] = 0.001;
    english_freq['k'] = 0.005;
    english_freq['l'] = 0.033;
    english_freq['m'] = 0.020;
    english_freq['n'] = 0.057;
    english_freq['o'] = 0.062;
    english_freq['p'] = 0.015;
    english_freq['q'] = 0.002;
    english_freq['r'] = 0.049;
    english_freq['s'] = 0.051;
    english_freq['t'] = 0.072;
    english_freq['u'] = 0.022;
    english_freq['v'] = 0.008;
    english_freq['w'] = 0.017;
    english_freq['x'] = 0.001;
    english_freq['y'] = 0.014;
    english_freq['z'] = 0.001;
    english_freq[' '] = 0.183;
    
    unsigned char key = 0;
    double max_score = -1;

    int k;
    size_t i;
    for (k = 0; k < 256; ++k) {
        unsigned char *decoded = malloc(len);
        for (i = 0; i < len; ++i) {
            decoded[i] = ciphertext[i] ^ k;
        }

        double freq[256] = {0};
        calc_freq(decoded, len, freq);

        double score = 0;
        for (i = 0; i < 256; ++i) {
            score += freq[i] * english_freq[i];
        }

        if (score > max_score) {
            max_score = score;
            key = k;
        }

        free(decoded);
    }

    return key;
}

void xor_bruteforce(char* ciphertext_hex) {
    size_t length = strlen(ciphertext_hex) / 2;
    uint8_t ciphertext[length+1];

    hex_to_bytes(ciphertext_hex, ciphertext, length);
    ciphertext[length] = '\0';

    int keysize = find_probable_keysize(ciphertext, length);

    char **blocks = malloc(keysize * sizeof(unsigned char *));
    transpose_blocks(ciphertext, blocks, length, keysize);

    size_t i;
    char *key = malloc(keysize + 1);
    for (i = 0; i < keysize; ++i) {
        key[i] = xor_bruteforce_single_key(blocks[i], keysize);
    }
    key[keysize] = '\0';

    unsigned char *plaintext = malloc(length + 1);
    for (i = 0; i < length; ++i) {
        plaintext[i] = ciphertext[i] ^ key[i % keysize];
    }
    plaintext[length] = '\0';

    printf("\nKey: %s", key);
    printf("\nPlaintext: %s\n", plaintext);

    free(plaintext);
    for (i = 0; i < keysize; ++i) {
        free(blocks[i]);
    }
    free(blocks);
    free(key);
}

int main(int argc, char *argv[])  {
    if (!handle_args(argc, argv))
        return 1;
    
    char *ciphertext_hex = argv[1];

    if (!check_valid_hex(ciphertext_hex)) {
        printf("\nerror: Invalid CIPHERTEXT. Only use hexadecimal characters.");
        return 1;
    }

    xor_bruteforce(ciphertext_hex);

    return 0;
}