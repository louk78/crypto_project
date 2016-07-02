#include "sha256.h"
#include "rsa.h"

#define MAX_SIGNATURE_LEN  2048

char * sign(char *message, int len, char *n, char *d)
{
    uint8_t hash[SHA256_HASH_LEN];
    char *dec_hash, *signature;
    sha256_ctx_t ctx;
    sha256_init(&ctx);

    signature = malloc(MAX_SIGNATURE_LEN);

    sha256_update(&ctx, message, len);
    sha256_finish(&ctx, hash);

    dec_hash = rsa_bin2dec(hash, SHA256_HASH_LEN);
    printf("Hash value (in dec):\n%s\n", dec_hash);
    rsa_encrypt(signature, dec_hash, strlen(dec_hash), n, d);
    free(dec_hash);
    printf("Signature result:\n%s\n", signature);
    return signature;
}

int verify(char *message, int len, char *n, char *e, char *signature)
{
    uint8_t hash[SHA256_HASH_LEN];
    char your_hash[MAX_SIGNATURE_LEN], *my_hash;
    int match;

    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, message, len);
    sha256_finish(&ctx, hash);
    my_hash = rsa_bin2dec(hash, SHA256_HASH_LEN);

    rsa_encrypt(your_hash, signature, strlen(signature), n, e);
    printf("Decrypted Hash value:\n%s\n", your_hash);
    if(strcmp(my_hash, your_hash) == 0)
        match = 1;
    else
        match = 0;
    free(my_hash);
    return match;
}
