RM=rm -f
CC=cc
CFLAGS=-g -Wall

all: conntest

conntest: conntest.o ike.o
	$(CC) -o conntest conntest.o ike.o

clean: 
	-$(RM) conntest conntest.o ike.o
