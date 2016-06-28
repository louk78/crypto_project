#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"

static void print_hex(uint8_t *ptr, int len)
{
    int i;
    for(i = 0; i < len; i++)
        printf("%2.2x ", ptr[i]);
    printf("\n");
}

void aes_128_test()
{
    uint8_t key[16] = {};
    uint8_t plaintext[16] = "abcdefghijklnm";
    uint8_t ciphertext[16];
    uint8_t decrypted[16];

    aes_ctx_t *ctx;
    ctx = AES_ctx_alloc(key, 16);

    AES_encrypt(ctx, plaintext, ciphertext);
    AES_decrypt(ctx, ciphertext, decrypted);
    free(ctx);

    puts("*********AES-128*********");
    printf("plaintext: %s\n", plaintext);
    printf("encrypted:\n");
    print_hex(ciphertext, 16);
    printf("decrypted: %s\n", decrypted);
}

void aes_256_test()
{
    uint8_t key[32] = {};
    uint8_t plaintext[16] = "I'm plaintext";
    uint8_t ciphertext[16];
    uint8_t decrypted[16];

    aes_ctx_t *ctx;
    ctx = AES_ctx_alloc(key, 32);

    AES_encrypt(ctx, plaintext, ciphertext);
    AES_decrypt(ctx, ciphertext, decrypted);
    free(ctx);

    puts("*********AES-256**********");
    printf("plaintext: %s\n", plaintext);
    printf("encrypted:\n");
    print_hex(ciphertext, 16);
    printf("decrypted: %s\n", decrypted);
}

int main()
{
    aes_128_test();
    aes_256_test();
    aes_128_cbc_test();
}
