#ifndef __AES_H__
#define __AES_H__

#include <stdint.h>
#include <stdlib.h>

#define AES_BLOCKSIZE 16

typedef struct {
    uint8_t state[4][4];
    int rounds;
    int keylen;
    uint8_t roundkey[0];    //allocate memory at runtime according to keysize
} aes_ctx_t;

void AES_encrypt(aes_ctx_t *ctx, uint8_t *in, uint8_t *out);

void AES_decrypt(aes_ctx_t *ctx, uint8_t *in, uint8_t *out);

aes_ctx_t * AES_ctx_alloc(uint8_t *key, size_t keylen);
#endif
