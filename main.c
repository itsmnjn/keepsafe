#include "keepsafe.h"

int main(int argc, char** argv)
{
        if (argv[1] == NULL) {
                printf("Usage: %s <option> <filename>\n", argv[0]);
                printf("Options:\n");
                printf("\t[default]\tencrypt <filename>\n");
                printf("\t-d\t\tdecrypt <filename>\n");

                return EXIT_FAILURE;
        }

        switch (argv[1]) {
        case "-d":
                if (fopen(argv[1], "r")) {
                        encrypt_mode(argv[1]);
                }
        }

        unsigned char *path = (unsigned char *) argv[1];

        printf("File \"%s\" selected...\n", path);
        unsigned char *passphrase = (unsigned char *) getpass(
                "Enter a passphrase to encrypt: ");

        return EXIT_SUCCESS;
}