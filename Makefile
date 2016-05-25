CC=gcc
CFLAGS=-c -Wall

all: aes

aes: aes.o aes_main.o
	$(CC) aes_main.o aes.o -o aes

aes.o: aes.c
	$(CC) $(CFLAGS) aes.c

aes_main.o:
	$(CC) $(CFLAGS) aes_main.c

