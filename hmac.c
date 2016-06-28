#include "sha256.h"
#include <stdio.h>


void hmac_sha256(uint8_t *data, unsigned long length, uint8_t *key, unsigned int keylen, uint8_t *mac_value)
{
    uint8_t ikey[SHA256_BLOCK_SIZE], okey[SHA256_BLOCK_SIZE];
    uint8_t hash[SHA256_HASH_LEN];
    sha256_ctx_t ctx;
    int i;

    for(i = 0; i < SHA256_BLOCK_SIZE; i++)
    {
        if(i < keylen)
        {
            ikey[i] = key[i] ^ 0x36;
            okey[i] = key[i] ^ 0x5c;
        }
        else
        {
        ikey[i] = 0x36;
        okey[i] = 0x5c;
        }
    }

    sha256_init(&ctx);
    sha256_update(&ctx, ikey, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, data, length);
    sha256_finish(&ctx, hash);

    sha256_init(&ctx);
    sha256_update(&ctx, okey, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, hash, SHA256_HASH_LEN);
    sha256_finish(&ctx, mac_value);
}
