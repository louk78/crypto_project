#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sha256.h"
#include "hmac.h"
#include "rsa.h"
#include "bignum.h"
#include "sign.h"


char message[] = "If someone loves a flower, of which just one single blossom \
grows in all the millions and millions of stars, it is enough to make him \
happy just to look at the stars. He can say to himself, \"Somewhere, my \
flower is there...\" But if the sheep eats the flower, in one moment all his \
stars will be darkened... And you think that is not important!";

char n[] = "2633080698619971615437014920877996278289800735266923785544426889944\
0609476923080683027336422535126368322315074618477456816398312119637107174579114\
6077889271153062424857361678839770414279603418258155137950669839476924880367722\
7208754742309849130234906643942284202464540412162804353349325546974376995059994\
9330325414410987655903196060428517308136957636128192517521032855823390274073501\
3439285983045554313762834966326627260773872229023350480565433033059416766300354\
3887701136666299285622928321437845693875410943358836663939407517138169975952711\
275846765751052131139716555711355334713006212037080193708644870739003106023";

char d[] = "1534955005102752603929712492582465707392358566400470260398774839789\
4934889672823592887074193372766370351195859772623603896884885924863886807706002\
7938585710836982931342203312897564505231339737103623651425536893524351182472794\
2027649848012582902905561935678338888913802659008057450433739864083753793978570\
8323755112163962040283206669767339836307290354653158546139557266465579456201338\
3640633190584017214343503798689012135964734952444966804075760697120758901874182\
4461444633608054278015035978191475115533914789852447157474083845793224473202128\
57398343699866494688143223633808351948490217995252693651367403612040470935";

char e[] = "1730645815";


void print_hex(uint8_t *ptr, int len)
{
    int i;
    for (i = 0; i < len; i++)
        printf("%2.2x", ptr[i]);
    printf("\n");
}

void sha256_test()
{
    int len;
    uint8_t hash[SHA256_HASH_LEN];
    sha256_ctx_t ctx;
    sha256_init(&ctx);

    len = strlen(message);

    sha256_update(&ctx, message, len);
    sha256_finish(&ctx, hash);

    printf("************SHA-256*************\n");
    printf("message:\n%s\n", message);
    printf("digest:\n");
    print_hex(hash, SHA256_HASH_LEN);
}

void hmac_sha256_test()
{
    uint8_t key[] = "secretkey";
    uint8_t mac[SHA256_HASH_LEN];
    int keylen, msglen;

    keylen = strlen(key);
    msglen = strlen(message);

    printf("************HMAC-SHA-256*************\n");
    hmac_sha256(message, msglen, key, keylen, mac);
    print_hex(mac, SHA256_HASH_LEN);
}

void rsa_key_gen_test()
{
    char d[2048], e[2048], n[2048];
    printf("************RSA_KEY_GEN*************\n");
    rsa_generate_key_pair(n, d, e, NULL, 128);
    printf("n=%s\nd=%s\ne=%s\n",n,d,e);
}

void rsa_signature_test()
{
    char *signature;
    int match;
    puts("************RSA Sigature*************");
    signature = sign(message, strlen(message), n, d);
    match = verify(message, strlen(message), n, e, signature);
    if(match)
        puts("match!");
    else
        puts("no match!");
}

int main()
{
    sha256_test();
    hmac_sha256_test();
    rsa_key_gen_test();
    rsa_signature_test();
    return 0;
}
