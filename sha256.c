#include "sha256.h"
// #include "stdio.h"

#define ROTR(x,n)   (((x) >> n) | ((x) << (32 - n)))

//round constants
static const uint32_t K[64] = {
     0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
     0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
     0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
     0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
     0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
     0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
     0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
     0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
     0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void compress(sha256_ctx_t *ctx);
static void bit_len_add(sha256_ctx_t *ctx, uint32_t val);

void sha256_init(sha256_ctx_t *ctx)
{
    ctx->buf_len = 0;
    ctx->bit_len[0] = ctx->bit_len[1] = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

void sha256_update(sha256_ctx_t *ctx, uint8_t *message, uint32_t len)
{
    uint32_t i;
    for(i = 0; i < len;i ++)
    {
        ctx->buf[ctx->buf_len] = message[i];
        ctx->buf_len++;
        if(ctx->buf_len == SHA256_BLOCK_SIZE)  //a chunk is ready
        {
            compress(ctx);
            bit_len_add(ctx, SHA256_BLOCK_SIZE * 8);
            ctx->buf_len = 0;
        }
    }
}

void sha256_finish(sha256_ctx_t *ctx, uint8_t *hash)
{
    register uint32_t i;
    i = ctx->buf_len;

    //add padding 1000...
    if(i < 56)
    {
        ctx->buf[i++] = 0x80;
        while(i < 56)
            ctx->buf[i++] = 0;
    }
    else
    {
        ctx->buf[i++] = 0x80;
        while(i < 64)
            ctx->buf[i++] = 0;
        compress(ctx);
        memset(ctx->buf, 0, 56);
    }

    //append total lenth in bits to message
    bit_len_add(ctx, ctx->buf_len * 8);

    //add to buf, Big Endian
    for (i = 0; i < 4; i++)
    {
        ctx->buf[63-i] = ctx->bit_len[0] >> (i*8);
        ctx->buf[59-i] = ctx->bit_len[1] >> (i*8);
    }
    compress(ctx);

    //convert to Big-Endian and output
    for (i = 0; i < 32; i++)
    {
        hash[i] = (ctx->state[i/4] >> (24 - 8*(i%4))) & 0x000000ff;
    }
}

static void bit_len_add(sha256_ctx_t *ctx, uint32_t val)
{
    if (ctx->bit_len[0] > 0xffffffff - val)
        ctx->bit_len[1]++;
    ctx->bit_len[0] += val;
}

static void compress(sha256_ctx_t *ctx)
{
    uint32_t b[8];
    uint32_t w[64]; //message schedule array
    uint32_t t1, t2, s0, s1;
    int i, j;

    for(i = 0; i < 8; i++)
    {
        b[i] = ctx->state[i];
        // printf("b[%d] = %x\n", i, b[i]);
    }

    //copy chunk into first 16 words of the message schedule array
    for (i = j = 0; i < 16; i++, j+=4)
    {
        w[i] = (ctx->buf[j] << 24) | (ctx->buf[j+1] << 16) | (ctx->buf[j+2] << 8) | (ctx->buf[j+3]);
    }

    //extend W array
    for(i = 16; i < 64; i++)
    {
        t1 = ROTR(w[i-15], 7) ^ ROTR(w[i-15], 18) ^ (w[i-15] >> 3);
        t2 = ROTR(w[i-2], 17) ^ ROTR(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + t1 + w[i-7] + t2;
    }

    //main loop
    for(i = 0; i < 64; i++)
    {
        s1 = ROTR(b[4], 6) ^ ROTR(b[4], 11) ^ ROTR(b[4], 25);
        t1 = b[7] + s1 + K[i] + w[i] + ((b[4] & b[5]) ^ ((~b[4]) & b[6]));
        s0 = ROTR(b[0], 2) ^ ROTR(b[0], 13) ^ ROTR(b[0], 22);
        t2 = s0 + ((b[0] & b[1]) ^ (b[0] & b[2]) ^ (b[1] & b[2]));

        b[7] = b[6];
        b[6] = b[5];
        b[5] = b[4];
        b[4] = b[3] + t1;
        b[3] = b[2];
        b[2] = b[1];
        b[1] = b[0];
        b[0] = t1 + t2;
    }

    // printf("%x\t%x\t%x\t%x\n", b[0], b[1], b[2], b[3]);
    // printf("%x\t%x\t%x\t%x\n", b[4], b[5], b[6], b[7]);

    for(i = 0; i < 8; i++)
        ctx->state[i] += b[i];
}
