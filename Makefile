CC=gcc
CFLAGS=-c -Wall

all: aes

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

aes_cmac.o: aes_cmac.c aes_cmac.h
	$(CC) $(CFLAGS) aes_cmac.c
