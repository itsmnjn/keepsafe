#include "tomcrypt.h"

void register_aes();

unsigned char * generate_key(const char *passphrase);

unsigned char * set_IV();

unsigned char * extract_IV(const char *path);

void file_to_buffer(const char *path, unsigned char *buffer, size_t size);

void buffer_to_file(
        const char *path,
        unsigned char *buffer,
        size_t size,
        const unsigned char *IV);

char * generate_enc_path(const char *path);

void print_data(unsigned char *buffer, size_t size);

void init(
        const unsigned char *IV,
        const unsigned char *key,
        symmetric_CTR *ctr);

void encrypt(
        const unsigned char *plaintext,
        unsigned char *ciphertext,
        unsigned long len,
        symmetric_CTR *ctr);

int main(int argc, char** argv)
{
        FILE* file;

        if (argv[1] == NULL) {
                printf("Usage: %s <filename>\n", argv[0]);
                return EXIT_FAILURE;
        } else if ((file = fopen(argv[1], "r")) == NULL) {
                printf("File \"%s\" not found.\n", argv[1]);
                return EXIT_FAILURE;
        }

        char *path = argv[1];

        printf("File \"%s\" found.\n", argv[1]);

        unsigned char *key, *IV, buffer[512], enc_data[512];
        symmetric_CTR ctr;
        int x, err;

        printf("Testing random encryption...\n");

        register_aes();
        
        printf("Filling out key and IV...\n");

        key = generate_key("password");
        IV = set_IV();

        printf("Key is: ");
        print_data(key, 16);

        printf("IV is: ");
        print_data(IV, 16);

        printf("Starting CTR mode\n");

        init(IV, key, &ctr);

        printf("Encrypting buffer!\n");

        file_to_buffer(path, buffer, 512);

        printf("Size of buffer: %d\n", (int) sizeof(buffer));

        encrypt(buffer, enc_data, sizeof(buffer), &ctr);

        char *enc_path = generate_enc_path(path);

        printf("Writing encrypted buffer into file \"%s\"\n", enc_path);

        buffer_to_file(enc_path, enc_data, 512, IV);

        printf("Decrypting buffer!\n");

        if (*IV != *extract_IV(enc_path)) {
                printf("IV extraction failed\n");
                exit(EXIT_FAILURE);
        }

        if ((err = ctr_setiv(IV, 16, &ctr)) != CRYPT_OK) {
                printf("ctr_setiv error: %s\n", error_to_string(err));
                return EXIT_FAILURE;
        }

        if ((err = ctr_decrypt(
                buffer,
                buffer,
                sizeof(buffer),
                &ctr)
            ) != CRYPT_OK) {
                printf("ctr_decrypt error: %s\n", error_to_string(err));
                return EXIT_FAILURE;
        }

        printf("Terminating stream...\n");

        if ((err = ctr_done(&ctr)) != CRYPT_OK) {
                printf("ctr_done error: %s\n", error_to_string(err));
                return EXIT_FAILURE;
        }

        zeromem(key, sizeof(key));
        zeromem(&ctr, sizeof(ctr));

        return EXIT_SUCCESS;
}

void register_aes()
{
        /* register aes */
        if (register_cipher(&aes_desc) == -1) {
                printf("Error registering cipher\n");
                exit(EXIT_FAILURE);
        }
}

unsigned char * generate_key(const char *passphrase)
{
        unsigned char* key = malloc(16 * sizeof(char));
        memcpy(key, "AAAAAAAAAAAAAAAA", 16);

        return key;
}

unsigned char * set_IV()
{
        unsigned char *IV = malloc(16 * sizeof(char));
        arc4random_buf(IV, 16);
        return IV;
}

unsigned char * extract_IV(const char *path)
{
        unsigned char *IV = malloc(16 * sizeof(char));
        FILE *file = fopen(path, "r");
        fread(IV, 1, 16, file);
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
        unsigned char *enc_data = malloc((size + 16) * sizeof(char));

        memcpy(enc_data, IV, 16);
        memcpy(enc_data + 16, buffer, size);

        if ((fwrite(enc_data, 1, size + 16, file)) != size + 16) {
                printf("Error writing encrypted data into file\n");
                exit(EXIT_FAILURE);
        }

        fclose(file);
}

char * generate_enc_path(const char *path)
{
        char *enc_path = malloc(strlen(path) + 5);
        
        strcpy(enc_path, path);
        strcat(enc_path, ".enc");

        return enc_path;
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
                16,
                0,
                CTR_COUNTER_LITTLE_ENDIAN,
                ctr)
        ) != CRYPT_OK) {
                printf("ctr_start error: %s\n", error_to_string(err));
                exit(EXIT_FAILURE);
        }
}

void encrypt(
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