#include "keepsafe.h"

void usage(char* filename)
{
        fprintf(stderr, "Usage: %s <option> <filename>\n", filename);
        fprintf(stderr, "Options:\n");
        fprintf(stderr, "\t[default]\tencrypt <filename>\n");
        fprintf(stderr, "\t-d\t\tdecrypt <filename>\n");

        exit(EXIT_FAILURE);
}

int main(int argc, char** argv)
{
        int opt;

        if (argv[1] == NULL) {
                usage(argv[0]);
        }

        while ((opt = getopt(argc, argv, "d:")) != -1) {
                switch (opt) {
                case 'd':
                        decrypt_mode(optarg);
                        break;
                default:
                        usage(argv[0]);
                        break;
                }
        }

        encrypt_mode(argv[1]);

        return EXIT_SUCCESS;
}