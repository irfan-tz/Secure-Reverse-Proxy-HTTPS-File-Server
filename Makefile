CC = gcc
CFLAGS = -Wall -Wextra -g -I/usr/include -I/usr/local/include
LDFLAGS = -L/usr/lib -L/usr/local/lib -lssl -lcrypto -lpam -lpthread

all: proxy client

proxy: src/proxy/proxy.c
	$(CC) $(CFLAGS) -o proxy src/proxy/proxy.c $(LDFLAGS)

client: src/client/client.c
	$(CC) $(CFLAGS) -o client src/client/client.c -lssl -lcrypto

clean:
	rm -f proxy client

.PHONY: all clean
