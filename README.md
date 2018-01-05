# Keepsafe

Easily encrypt/decrypt your files with a passphrase. Uses AES-256 for encryption, hashing the passphrase with SHA-256 to use as the key. Cryptography algorithms are provided by [LibTomCrypt](https://github.com/libtom/libtomcrypt).

## Dependencies

None. The LibTomCrypt library is included with the source, and is statically compiled.

## Installation

Clone this repository, `cd` into it, and run `make`. Simple as that.

## Usage

```
./keepsafe <file to encrypt>
./keepsafe -d <file to decrypt>
```

Encrypted files will be placed in the current working directory with the extension `.enc` appended.

Decrypted files will have `.dec` appended, instead.

**Note:** Keepsafe will not warn upon an incorrect passphrase being entered to decrypt a file. The "decrypted" file will just turn out to be unreadable junk. Couldn't figure out a way to verify the correct key 🤷‍