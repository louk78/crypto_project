#ifndef __RSA_H__
#define __RSA_H__

#include "bignum.h"

void rsa_generate_key_pair(char *n, char *d, char *e, char *phi, int bytes);
void rsa_encrypt(char *result, char *plaintext, int bytes, char *modulus, char *exponent);
void rsa_decrypt(char *result, char *ciphertext, int bytes, char *modulus, char *exponent);
char * rsa_bin2dec(uint8_t *bin, int len);
#endif
