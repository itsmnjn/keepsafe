#include "keepsafe.h"

void register_aes()
{
        /* register aes */
        if (register_cipher(&aes_desc) == -1) {
                printf("Error registering cipher\n");
                exit(EXIT_FAILURE);
        }
}

unsigned char * hash(const unsigned char *in)
{
        hash_state sha;
        unsigned char *out = malloc(32 * sizeof(char));

        sha256_init(&sha);
        sha256_process(&sha, in, strlen((const char *) in));
        sha256_done(&sha, out);

        return out;
}

unsigned char * generate_key(const char *passphrase)
{
        unsigned char* key = hash((const unsigned char *) passphrase);
        return key;
}

unsigned char * gen_IV()
{
        unsigned char *IV = malloc(32 * sizeof(char));
        arc4random_buf(IV, 32);
        return IV;
}

void set_IV(const unsigned char* IV, symmetric_CTR *ctr)
{
        int err;

        if ((err = ctr_setiv(IV, 32, ctr)) != CRYPT_OK) {
                printf("ctr_setiv error: %s\n", error_to_string(err));
                exit(EXIT_FAILURE);
        }
}

unsigned char * extract_IV(const char *path)
{
        unsigned char *IV = malloc(32 * sizeof(char));
        FILE *file = fopen(path, "r");
        fread(IV, 1, 32, file);
        fclose(file);

        return IV;
}

void file_to_buffer(const char *path, unsigned char* buffer, size_t size)
{
        FILE *file = fopen(path, "rb");
        
        if(!(fread(buffer, 1, size, file))) {
                printf("Error reading file into buffer\n");
                return exit(EXIT_FAILURE);
        }

        fclose(file);
}

void buffer_to_file(
        const char *path,
        unsigned char *buffer,
        size_t size,
        const unsigned char* IV)
{
        FILE *file = fopen(path, "ab+");
        unsigned char *enc_data = malloc((size + 32) * sizeof(char));

        memcpy(enc_data, IV, 32);
        memcpy(enc_data + 32, buffer, size);

        if ((fwrite(enc_data, 1, size + 32, file)) != size + 32) {
                printf("Error writing encrypted data into file\n");
                exit(EXIT_FAILURE);
        }

        fclose(file);
        free(enc_data);
}

char * generate_enc_path(const char *path)
{
        char *enc_path = malloc(strlen(path) + 5);
        
        strcpy(enc_path, path);
        strcat(enc_path, ".enc");

        return enc_path;
}

char * generate_dec_path(const char *path)
{
        char *dec_path = malloc(strlen(path) + 5);
        
        strcpy(dec_path, path);
        strcat(dec_path, ".dec");

        return dec_path;
}

void print_data(unsigned char *buffer, size_t size)
{
        for (int i = 0; i < size; i++) {
                printf("%x", buffer[i]);
        }
        printf("\n");
}

void init(
        const unsigned char *IV,
        const unsigned char *key,
        symmetric_CTR *ctr)
{
        int err;

        if ((err = ctr_start(
                find_cipher("aes"),
                IV,
                key,
                32,
                0,
                CTR_COUNTER_LITTLE_ENDIAN,
                ctr)
        ) != CRYPT_OK) {
                printf("ctr_start error: %s\n", error_to_string(err));
                exit(EXIT_FAILURE);
        }
}

void aes_encrypt(
        const unsigned char *plaintext,
        unsigned char *ciphertext, 
        unsigned long len,
        symmetric_CTR *ctr)
{
        int err;

        if ((err = ctr_encrypt(
                plaintext,
                ciphertext,
                len,
                ctr)
            ) != CRYPT_OK) {
                printf("ctr_encrypt error: %s\n", error_to_string(err));
                exit(EXIT_FAILURE);
        }
}

void aes_decrypt(
        const unsigned char *ciphertext,
        unsigned char *plaintext,
        unsigned long len,
        symmetric_CTR *ctr)
{
        int err;

        if ((err = ctr_decrypt(
                ciphertext,
                plaintext,
                sizeof(ciphertext),
                ctr)
            ) != CRYPT_OK) {
                printf("ctr_decrypt error: %s\n", error_to_string(err));
                exit(EXIT_FAILURE);
        }
}

void encrypt_mode(char *path)
{

}

void decrypt_mode(char *path)
{

}

void done(symmetric_CTR *ctr)
{
        int err;

        if ((err = ctr_done(ctr)) != CRYPT_OK) {
                printf("ctr_done error: %s\n", error_to_string(err));
                exit(EXIT_FAILURE);
        }
}