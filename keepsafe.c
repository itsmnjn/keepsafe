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

unsigned char * extract_IV(FILE *file)
{
        unsigned char *IV = malloc(32 * sizeof(char));
        fread(IV, 1, 32, file);
        fseek(file, 0L, SEEK_SET);
        return IV;
}

void file_to_buffer(FILE *file, unsigned char* buffer, size_t size)
{       
        if(!(fread(buffer, 1, size, file))) {
                printf("Error reading file into buffer\n");
                return exit(EXIT_FAILURE);
        }

        fseek(file, 0L, SEEK_SET);
}

void enc_buffer_to_file(
        const char *path,
        unsigned char *buffer,
        size_t size,
        const unsigned char* IV)
{
        FILE *file;
        unsigned char *enc_data = malloc((size + 32) * sizeof(char));

        memcpy(enc_data, IV, 32);
        memcpy(enc_data + 32, buffer, size);

        if ((file = fopen(path, "ab")) == NULL) {
                fprintf(stderr, "Error: unable to create file \"%s\".\n", path);
                exit(EXIT_FAILURE);
        }

        if ((fwrite(enc_data, 1, size + 32, file)) != size + 32) {
                fprintf(stderr, "Error: unable to write encrypted data into file \"%s\".\n", path);
                exit(EXIT_FAILURE);
        }

        fclose(file);
        free(enc_data);
}

void dec_buffer_to_file(
        const char *path,
        unsigned char *buffer,
        size_t size)
{
        FILE *file;

        if ((file = fopen(path, "ab")) == NULL) {
                fprintf(stderr, "Error: unable to create file \"%s\".\n", path);
                exit(EXIT_FAILURE);
        }

        if ((fwrite(buffer, 1, size, file)) != size) {
                fprintf(stderr, "Error: unable to write encrypted data into file \"%s\".\n", path);
                exit(EXIT_FAILURE);
        }

        fclose(file);
}

size_t get_fsize(FILE *file)
{
        long start;
        size_t size;

        start = ftell(file);
        fseek(file, 0L, SEEK_END);
        size = (size_t) ftell(file);
        fseek(file, start, SEEK_SET);

        return size;
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
        char *dec_path = malloc(strlen(path) + 1);
        
        strcpy(dec_path, path);
        strcat(dec_path, ".dec");

        return dec_path;
}

void print_data(unsigned char *buffer, size_t size, char mode)
{
        switch(mode) {
        case 'x':
                for (int i = 0; i < size; i++) {
                        printf("%x", buffer[i]);
                }
                printf("\n");
                break;
        case 'c':
                for (int i = 0; i < size; i++) {
                        printf("%c", buffer[i]);
                }
                printf("\n");
                break;
        default:
                fprintf(stderr, "Error (in print_data): unrecognized mode.\n");
                break;
        }
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
                len,
                ctr)
            ) != CRYPT_OK) {
                printf("ctr_decrypt error: %s\n", error_to_string(err));
                exit(EXIT_FAILURE);
        }
}

void encrypt_mode(char *path)
{
        FILE *file;
        size_t fsize;
        char *enc_path;
        unsigned char *passphrase, *key, *IV, *plaintext, *ciphertext;
        symmetric_CTR *ctr = malloc(sizeof(symmetric_CTR));

        if ((file = fopen(path, "rb")) == NULL) {
                fprintf(stderr, "Error: file \"%s\" does not exist.\n", path);
                exit(EXIT_FAILURE);
        }

        printf("Encrypting file \"%s\"...\n", path);

        passphrase = (unsigned char *) getpass("Enter a passphrase: ");

        key = hash(passphrase);
        IV = gen_IV();
        fsize = get_fsize(file);
        plaintext = malloc(fsize * sizeof(char));
        ciphertext = malloc((fsize + 32) * sizeof(char));
        enc_path = generate_enc_path(path);

        file_to_buffer(file, plaintext, fsize);

        register_aes();
        init(IV, key, ctr);

        aes_encrypt(plaintext, ciphertext, fsize, ctr);

        enc_buffer_to_file(enc_path, ciphertext, fsize, IV);

        printf("File \"%s\" successfully encrypted into \"%s\"\n", path, enc_path);

        fclose(file);
        free(enc_path);
        free(key);
        free(IV);
        free(plaintext);
        free(ciphertext);
        free(ctr);

        exit(EXIT_SUCCESS);
}

void decrypt_mode(char *path)
{
        FILE *file;
        size_t fsize;
        char *dec_path;
        unsigned char *passphrase, *key, *IV, *plaintext, *ciphertext;
        symmetric_CTR *ctr = malloc(sizeof(symmetric_CTR));

        if ((file = fopen(path, "rb")) == NULL) {
                fprintf(stderr, "Error: file \"%s\" does not exist.\n", path);
                exit(EXIT_FAILURE);
        }

        printf("Decrypting file \"%s\"...\n", path);

        passphrase = (unsigned char *) getpass("Enter the passphrase: ");

        key = hash(passphrase);
        IV = extract_IV(file);
        fsize = get_fsize(file);
        plaintext = malloc((fsize - 32) * sizeof(char));
        ciphertext = malloc(fsize * sizeof(char));
        dec_path = generate_dec_path(path);

        file_to_buffer(file, ciphertext, fsize);

        register_aes();
        init(IV, key, ctr);

        aes_decrypt(ciphertext + 32, plaintext, fsize - 32, ctr); // +/- 32 is to account for prepended IV in encrypted file



        dec_buffer_to_file(dec_path, plaintext, fsize - 32);

        printf("File \"%s\" successfully decrypted into \"%s\"\n", path, dec_path);

        fclose(file);
        free(dec_path);
        free(key);
        free(IV);
        free(plaintext);
        free(ciphertext);
        free(ctr);

        exit(EXIT_SUCCESS);
}

void done(symmetric_CTR *ctr)
{
        int err;

        if ((err = ctr_done(ctr)) != CRYPT_OK) {
                printf("ctr_done error: %s\n", error_to_string(err));
                exit(EXIT_FAILURE);
        }
}