CC=cc
CFLAGS=-Wall
LIBS=-lsodium -lsqlite3

all: xsqlite3

%.o: %.c
	$(CC) $(CFLAGS) $< $(LIBS) -c

xsqlite3: xsqlite3.o shell.o
	$(CC) $(CFLAGS) $^ $(LIBS) -o $@ 

clean:
	rm -f *.o xsqlite
