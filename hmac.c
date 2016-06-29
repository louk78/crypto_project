#include "sha256.h"
#include <stdio.h>


void hmac_sha256(uint8_t *data, unsigned long length, uint8_t *key, unsigned int keylen, uint8_t *mac_value)
{
    uint8_t ikey[SHA256_BLOCK_SIZE], okey[SHA256_BLOCK_SIZE];
    uint8_t hash[SHA256_HASH_LEN];
    sha256_ctx_t ctx;
    int i;

    if(keylen <= SHA256_BLOCK_SIZE)
    {
        memset(ikey, 0, SHA256_BLOCK_SIZE);
        memset(okey, 0, SHA256_BLOCK_SIZE);
        memcpy(ikey, key, keylen);
        memcpy(okey, key, keylen);
    }
    else
    {
        sha256_init(&ctx);
        sha256_update(&ctx, key, keylen);
        sha256_finish(&ctx, ikey);
        memcpy(okey, ikey, SHA256_BLOCK_SIZE);
    }

    for(i = 0; i < SHA256_BLOCK_SIZE; i++)
    {
        ikey[i] = ikey[i] ^ 0x36;
        okey[i] = okey[i] ^ 0x5c;
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
