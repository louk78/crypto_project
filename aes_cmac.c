#include "aes.h"
#include "aes_cmac.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// #define DEBUG

static void print_block(uint8_t *ptr);
static void left_shift(uint8_t *dest, uint8_t *src);
static void gen_subkey(aes_ctx_t *aes_ctx, uint8_t *key, uint8_t *subkey_1, uint8_t *subkey_2);
static void block_xor_triple(uint8_t *a, uint8_t *b, uint8_t *c);
static void add_padding(uint8_t *block, int len);

void aes_cmac(uint8_t *input, unsigned long length, uint8_t *key, uint8_t *mac_value)
{
    uint8_t subkey_1[AES_BLOCKSIZE];
    uint8_t subkey_2[AES_BLOCKSIZE];
    uint8_t previous_block_ciphertext[AES_BLOCKSIZE] = {};
    uint8_t temp[AES_BLOCKSIZE];
    unsigned long i;
    aes_ctx_t *aes_ctx;

    aes_ctx = AES_ctx_alloc(key, 16);

    gen_subkey(aes_ctx, key, subkey_1, subkey_2);

    for(i = 0; i < length; i+= AES_BLOCKSIZE)
    {

#ifdef DEBUG
        printf("Position %lx\n", i);
        printf("M:\n");
        print_block(input);
        printf("IV:\n");
        print_block(previous_block_ciphertext);
#endif
        block_xor_triple(input, previous_block_ciphertext, temp);

#ifdef DEBUG
        printf("xored with IV:\n");
        print_block(temp);
#endif

        if(i + AES_BLOCKSIZE == length)
        {
            //the last block if full, xor with subkey_1
            block_xor_triple(temp, subkey_1, temp);
        }
        else if(i + AES_BLOCKSIZE > length)
        {
            //last block is not full, add padding
            add_padding(temp, length - i);
            block_xor_triple(temp, subkey_2, temp);
        }

#ifdef DEBUG
        printf("xored with key:\n");
        print_block(temp);
#endif

        AES_encrypt(aes_ctx, temp, previous_block_ciphertext);
        input += AES_BLOCKSIZE;
    }
    free(aes_ctx);
    memcpy(mac_value, previous_block_ciphertext, AES_BLOCKSIZE);
}

//put 0x80, 0x00, 0x00 after the first len bytes of block
static void add_padding(uint8_t *block, int len)
{
    int i;
    for(i = len; i < AES_BLOCKSIZE; i++)
        block[i] = 0;
    block[len] = 0x80;
}

static void block_xor_triple(uint8_t *a, uint8_t *b, uint8_t *c)
{
    int i;
    for(i = 0; i < AES_BLOCKSIZE; i++)
        c[i] = a[i] ^ b[i];
}

static void gen_subkey(aes_ctx_t *aes_ctx, uint8_t *key, uint8_t *subkey_1, uint8_t *subkey_2)
{
    uint8_t zeros[16] = {};
    uint8_t L[16];

    AES_encrypt(aes_ctx, zeros, L);

    left_shift(subkey_1, L);
    if(L[0] & 0x80)
        subkey_1[15] ^= 0x87;

    left_shift(subkey_2, subkey_1);
    if(subkey_1[0] & 0x80)
        subkey_2[15] ^= 0x87;

#ifdef DEBUG
    puts("K1:");
    print_block(subkey_1);
    puts("K2:");
    print_block(subkey_2);
#endif
}

static void left_shift(uint8_t *dest, uint8_t *src)
{
    int i;
    uint8_t overflow = 0;

    // print_block(src);
    for(i = 15; i >= 0; i--)
    {
        dest[i] = src[i] << 1;
        dest[i] |= overflow;
        overflow = (src[i] >> 7) & 1;
    }
    // print_block(dest);
}

static void print_block(uint8_t *ptr)
{
    int i;
    for(i = 0; i < 16; i++)
        printf("%2.2x ", ptr[i]);
    printf("\n");
}
