#ifndef __AES_CMAC_H__
#define __AES_CMAC_H__

#include <string.h>
#include <stdlib.h>

void aes_cmac(uint8_t *input, unsigned long length, uint8_t *key, uint8_t *mac_value);

#endif
