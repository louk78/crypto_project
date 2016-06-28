#include "aes.h"
#include "aes_cbc.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define block_copy(dest, src)  memcpy((dest), (src), AES_BLOCKSIZE)

static void block_xor(uint8_t *a, uint8_t *b);

unsigned long AES_CBC_encrypt(uint8_t *input, uint8_t *output, unsigned long length, uint8_t *key, size_t keylen, uint8_t *iv)
{
    aes_ctx_t *ctx;
    uint8_t *previous_block_ciphertext = iv;
    unsigned long i;
    unsigned long output_length;

    ctx = AES_ctx_alloc(key, keylen);

    for(i = 0; i < length; i+= AES_BLOCKSIZE)
    {
        block_copy(output, input);
        block_xor(output, previous_block_ciphertext);
        AES_encrypt(ctx, output, output);
        previous_block_ciphertext = output;

        output += AES_BLOCKSIZE;
        input += AES_BLOCKSIZE;
    }
    output_length = (length / AES_BLOCKSIZE) * AES_BLOCKSIZE;
    i = length % AES_BLOCKSIZE;
    if (i > 0)
    {
        // puts("additional block");
        //add zero padding
        memset(output, 0, AES_BLOCKSIZE);
        memcpy(output, input, i);
        block_xor(output, previous_block_ciphertext);
        AES_encrypt(ctx, output, output);
        output_length += AES_BLOCKSIZE;
    }
    free(ctx);

    return output_length;
}

void AES_CBC_decrypt(uint8_t *input, uint8_t *output, unsigned long length, uint8_t *key, size_t keylen, uint8_t *iv)
{
    aes_ctx_t *ctx;
    uint8_t *previous_block_ciphertext = iv;
    unsigned long i;

    ctx = AES_ctx_alloc(key, keylen);

    for(i = 0; i < length; i+= AES_BLOCKSIZE)
    {
        block_copy(output, input);
        AES_decrypt(ctx, output, output);
        block_xor(output, previous_block_ciphertext);

        previous_block_ciphertext = input;
        output += AES_BLOCKSIZE;
        input += AES_BLOCKSIZE;
    }

    i = length % AES_BLOCKSIZE;
    if(i > 0)
    {
        block_copy(output, input);
        AES_decrypt(ctx, output, output);
        block_xor(output, previous_block_ciphertext);
        memset(output + i, 0, AES_BLOCKSIZE - i);
    }
}

//a = a xor b
static void block_xor(uint8_t *a, uint8_t *b)
{
    int i;
    for(i = 0; i < AES_BLOCKSIZE; i++)
        a[i] ^= b[i];
}
