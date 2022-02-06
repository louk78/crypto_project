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

void aes_cmac_can_test()
{
    unsigned char key_auth[16] = {0x30, 0xC1, 0x37, 0xAA, 0x33, 0x85, 0xDE, 0x39, 0x07, 0xB3, 0x09, 0x4B, 0x03, 0x0C, 0xFD, 0x30};
	
    unsigned char out_mac[16];
    unsigned char pdu_in[18] = {0x03, 0x51, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x00, 0x16, 0x00, 0x01, 0x00, 0x00, 0x35};
    aes_cmac(pdu_in, sizeof(pdu_in), key_auth, out_mac);
    print_hex(out_mac, 16);
}

void aes_cbc_test()
{
    unsigned char aes_key[16] = {0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01};
    unsigned char aes_iv[16] = {0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02};
    char in[128] = "123456789agdugyasdgfyagsdvsdayfadfakdfggyu";
    unsigned char out[128];
    char tmp[128];
    int out_len;
    int tmp_len;

    memset(out, 0, sizeof(out));
    memset(tmp, 0, sizeof(tmp));

    out_len = AES_CBC_encrypt(in, out, strlen(in), aes_key, 16, aes_iv);
    print_hex(out, out_len);
    AES_CBC_decrypt(out, tmp, out_len, aes_key, 16, aes_iv);
    printf("%s\n", tmp);
}

int main()
{
    //aes_128_test();
    // aes_256_test();
    //aes_128_cbc_test();
    //aes_cmac_test();
    aes_cbc_test();
    aes_cmac_can_test();
}
