CC=cc
CFLAGS=-Wall
LIBS=-lsodium -lsqlite3
BIN_DEST=/usr/local/bin
NAME=xsqlite3

all: $(NAME)

%.o: %.c
	$(CC) $(CFLAGS) $< -c

$(NAME): $(NAME).o shell.o util.o
	$(CC) $(CFLAGS) $^ $(LIBS) -o $@ 

.PHONY: clean install uninstall

clean:
	rm -f *.o $(NAME)

install: all
	mkdir -p $(BIN_DEST)
	cp $(NAME) $(BIN_DEST)

uninstall:
	rm -f $(BIN_DEST)/$(NAME)
