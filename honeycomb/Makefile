
CC = gcc

POLARSSL = ../client/ssl/polarssl
INCLUDES = -I$(POLARSSL)/include -I../libs
LIBPOLARSSL = $(POLARSSL)/library/libpolarssl.a

CFLAGS = -Wall -m32
CFLAGS += $(INCLUDES) $(LDFLAGS)

DFLAGS = $(CFLAGS) -DDEBUG -D_DEBUG
DFLAGS += $(INCLUDES) $(LDFLAGS)

.PHONY: all
all: release debug

.PHONY: debug
debug: $(LIBPOLARSSL)
	gcc $(CFLAGS) $(DFLAGS) -o honeycomb-dbg ../client/ssl/crypto.c blth.c $(LIBPOLARSSL)
	md5sum honeycomb-dbg > honeycomb-dbg.md5

.PHONY: release
release: $(LIBPOLARSSL)
	gcc $(CFLAGS) -o honeycomb ../client/ssl/crypto.c blth.c $(LIBPOLARSSL)
	md5sum honeycomb > honeycomb.md5

$(LIBPOLARSSL):
	cd $(POLARSSL)/library && $(MAKE) -f Makefile.linux-x86

clean:
	rm -f honeycomb honeycomb-dbg *.o *.a core *.md5
	make -C $(POLARSSL)/library clean
