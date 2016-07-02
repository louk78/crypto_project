CC=gcc
CFLAGS=-c -Wall

all: aes signature

aes: aes.o aes_client.o aes_cbc.o aes_cmac.o
	$(CC) aes_client.o aes.o aes_cbc.o aes_cmac.o -o aes_client

aes.o: aes.c aes.h
	$(CC) $(CFLAGS) aes.c

aes_client.o: aes_client.c
	$(CC) $(CFLAGS) aes_client.c

aes_cbc.o: aes_cbc.c aes_cbc.h
	$(CC) $(CFLAGS) aes_cbc.c

clean:
	rm *.o
	rm aes_client
	rm signature_client

aes_cmac.o: aes_cmac.c aes_cmac.h
	$(CC) $(CFLAGS) aes_cmac.c

signature: sha256.o signature_client.o hmac.o bignum.o rsa.o sign.o
	$(CC) sha256.o signature_client.o hmac.o rsa.o bignum.o sign.o -o signature_client

sha256.o: sha256.h sha256.c
	$(CC) $(CFLAGS) sha256.c

hmac.o: hmac.c hmac.h
	$(CC) $(CFLAGS) hmac.c

bignum.o: bignum.c bignum.h
	$(CC) $(CFLAGS) bignum.c

signature_client.o: signature_client.c
	$(CC) $(CFLAGS) signature_client.c

bignum_test: bignum_test.c bignum.o
	$(CC) bignum_test.c bignum.o -o bignum_test

ras.o: rsa.c rsa.h
	$(CC) $(CFLAGS) rsa.c

sign.o: sign.c sign.h
	$(CC) $(CFLAGS) sign.c
