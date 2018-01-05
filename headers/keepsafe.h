#include <unistd.h>
#include <pwd.h>

#include "tomcrypt.h"

#ifndef KEEPSAFE_H
#define KEEPSAFE_H

void register_aes();

unsigned char * hash(const unsigned char *in);

unsigned char * generate_key(const char *passphrase);

unsigned char * gen_IV();

void set_IV(const unsigned char* IV, symmetric_CTR *ctr);

unsigned char * extract_IV(FILE *file);

void file_to_buffer(FILE *file, unsigned char *buffer, size_t size);

void enc_buffer_to_file(
        const char *path,
        unsigned char *buffer,
        size_t size,
        const unsigned char *IV);

size_t get_fsize(FILE *file);

char * generate_enc_path(const char *path);

char * generate_dec_path(const char *path);

void print_data(unsigned char *buffer, size_t size, char mode);

void init(
        const unsigned char *IV,
        const unsigned char *key,
        symmetric_CTR *ctr);

void aes_encrypt(
        const unsigned char *plaintext,
        unsigned char *ciphertext,
        unsigned long len,
        symmetric_CTR *ctr);

void aes_decrypt(
        const unsigned char *ciphertext,
        unsigned char *plaintext,
        unsigned long len,
        symmetric_CTR *ctr);

void encrypt_mode(char *path);

void decrypt_mode(char *path);

void done(symmetric_CTR *ctr);

#endif