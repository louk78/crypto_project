CC=gcc
CFLAGS=-c -Wall

all: aes

aes: aes.o aes_client.o
	$(CC) aes_client.o aes.o -o aes

aes.o: aes.c
	$(CC) $(CFLAGS) aes.c

aes_client.o: aes_client.c
	$(CC) $(CFLAGS) aes_client.c

clean:
	rm *.o
	rm aes
