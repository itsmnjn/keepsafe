LDFLAGS =
CFLAGS = -c -Wall -std=c99 -I headers
SOURCES = main.c keepsafe.c
LIB = lib/libtomcrypt.a
OBJ = $(SOURCES:.c=.o)
BIN = keepsafe

all: $(SOURCES) $(BIN)

$(BIN): $(OBJ)
	gcc $(LDFLAGS) $(OBJ) $(LIB) -o $(BIN)

$(OBJ): $(SOURCES)
	gcc $(CFLAGS) $(SOURCES)

clean:
	rm $(OBJ) $(BIN) *.enc
