#ifndef __HMAC_H__
#define __HMAC_H__


void hmac_sha256(uint8_t *data, unsigned long length, uint8_t *key, unsigned int keylen, uint8_t *mac_value);

#endif
