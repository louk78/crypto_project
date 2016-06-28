#ifndef __AES_CBC_H__
#define __AES_CBC_H__

#include <string.h>
#include <stdlib.h>

/*
input: pointer to input data
output: ..........output....
length: length of plaintext message
key: pointer to key
keylen: 16, 24 or 32
iv: initial vector for CBC mode
*/
unsigned long AES_CBC_encrypt(uint8_t *input, uint8_t *output, unsigned long length, uint8_t *key, size_t keylen, uint8_t *iv);
void AES_CBC_decrypt(uint8_t *input, uint8_t *output, unsigned long length, uint8_t *key, size_t keylen, uint8_t *iv);

#endif
