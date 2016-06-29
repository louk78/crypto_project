#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "aes_cbc.h"
#include "aes_cmac.h"

char teststring[] = "If someone loves a flower, of which just one single blossom \
grows in all the millions and millions of stars, it is enough to make him \
happy just to look at the stars. He can say to himself, \"Somewhere, my \
flower is there...\" But if the sheep eats the flower, in one moment all his \
stars will be darkened... And you think that is not important!";

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
    uint8_t plaintext[16] = "helloworld~";
    uint8_t ciphertext[16];
    uint8_t decrypted[16];

    aes_ctx_t *ctx;
    ctx = AES_ctx_alloc(key, 16);

    AES_encrypt(ctx, plaintext, ciphertext);
    AES_decrypt(ctx, ciphertext, decrypted);
    free(ctx);

    puts("\n*********AES-128*********");
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

    puts("\n*********AES-256**********");
    printf("plaintext: %s\n", plaintext);
    printf("encrypted:\n");
    print_hex(ciphertext, 16);
    printf("decrypted: %s\n", decrypted);
}

void aes_128_cbc_test()
{
    uint8_t *plaintext = teststring;
    uint8_t ciphertext[512], decrypted[512];
    uint8_t key[16] = "secretkey";
    uint8_t iv[16] = "initialvec";
    unsigned long ciphertext_len;
    unsigned long plaintext_len;

    puts("\n*********AES-128-CBC**********");
    plaintext_len = strlen(plaintext);

    ciphertext_len = AES_CBC_encrypt(plaintext, ciphertext, plaintext_len, key, 16, iv);
    printf("key:\n");
    print_hex(key, 16);
    printf("iv:\n");
    print_hex(iv, 16);

    printf("plaintext: %lu bytes\n%s\n", plaintext_len, plaintext);
    printf("ciphertext: %lu bytes\n", ciphertext_len);
    print_hex(ciphertext, ciphertext_len);

    AES_CBC_decrypt(ciphertext, decrypted, plaintext_len, key, 16, iv);
    printf("decrypted:\n%s\n", decrypted);
}

void aes_cmac_test()
{
    uint8_t key[16] = "secretkey";
    uint8_t mac[16];
    uint8_t *input = teststring;

    puts("\n*********AES-CMAC**********");
    aes_cmac(input, strlen(input), key, mac);
    printf("message:\n%s\n", input);
    printf("key: %s\n", key);
    printf("CMAC result:\n");
    print_hex(mac, 16);
}

int main()
{
    aes_128_test();
    // aes_256_test();
    aes_128_cbc_test();
    aes_cmac_test();
}
