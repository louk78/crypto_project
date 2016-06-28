#ifndef __SHA256_H__
#define __SHA256_H__

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define SHA256_BLOCK_SIZE  64
#define SHA256_HASH_LEN 32

typedef struct {
    uint8_t buf[64];   //512bit chunks
    uint32_t state[8];   //256bit hash value
    uint32_t buf_len;   //bytes in buf
    uint32_t bit_len[2];    //total length in bits
} sha256_ctx_t;

void sha256_init(sha256_ctx_t *ctx);
void sha256_update(sha256_ctx_t *ctx, uint8_t *message, uint32_t len);
void sha256_finish(sha256_ctx_t *ctx, uint8_t *hash);


#endif
