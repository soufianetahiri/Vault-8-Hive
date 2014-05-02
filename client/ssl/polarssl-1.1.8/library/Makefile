
# Also see "include/polarssl/config.h"

CFLAGS	= -I../include -Wall -W -Wdeclaration-after-statement
OFLAGS	= -O2

ifeq ("$(TARGET)", "linux-x86")
	include ../../../Makefile-include.linux-x86
endif
ifeq ("$(TARGET)", "linux-x86_64")
	include ../../../Makefile-include.linux-x86_64
endif
ifeq ("$(TARGET)", "mikrotik-mips")
	include ../../../Makefile-include.mikrotik-mips
endif
ifeq ("$(TARGET)", "mikrotik-mipsel")
	include ../../../Makefile-include.mikrotik-mipsel
endif
ifeq ("$(TARGET)", "mikrotik-x86")
	include ../../../Makefile-include.mikrotik-x86
endif
ifeq ("$(TARGET)", "mikrotik-ppc")
	include ../../../Makefile-include.mikrotik-ppc
endif
ifeq ("$(TARGET)", "arm")
	include ../../../Makefile-include.arm
endif
ifeq ("$(TARGET)", "solaris-sparc")
	include ../../../Makefile-include.solaris-sparc
endif
ifeq ("$(TARGET)", "solaris-x86")
	include ../../../Makefile-include.solaris-x86
endif

ifdef DEBUG
CFLAGS += -g3
CFLAGS += -DPOLARSSL_DEBUG_C -DPOLARSSL_DEBUG_MSG
endif


# MicroBlaze specific options:
# CFLAGS += -mno-xl-soft-mul -mxl-barrel-shift

# To compile on Plan9:
# CFLAGS += -D_BSD_EXTENSION

# To compile as a shared library:
# CFLAGS += -fPIC

SONAME=libpolarssl.so.0

DLEXT=so
# OSX shared library extension:
# DLEXT=dylib

# Windows shared library extension:
# DLEXT=dll

OBJS=	aes.o		arc4.o		asn1parse.o		\
		base64.o	bignum.o	camellia.o		\
		certs.o		cipher.o	cipher_wrap.o	\
		ctr_drbg.o	debug.o		des.o			\
		dhm.o		entropy.o	entropy_poll.o	\
		error.o		havege.o					\
		md.o		md_wrap.o	md2.o			\
		md4.o		md5.o		net.o			\
		padlock.o	pem.o		pkcs11.o		\
		rsa.o		sha1.o		sha2.o			\
		sha4.o		ssl_cli.o	ssl_srv.o		\
		ssl_tls.o	timing.o	version.o		\
		x509parse.o	xtea.o				\
		loki_utils.o
	

.SILENT:

all: static

static: libpolarssl.a

shared: libpolarssl.$(DLEXT)

libpolarssl.a: $(OBJS)
	echo "  AR    $@"
	$(AR) r $@ $(OBJS)
	echo "  RL    $@"
	$(AR) s $@

libpolarssl.so: libpolarssl.a
	echo "  LD    $@"
	$(CC) ${LDFLAGS} -shared -Wl,-soname,$(SONAME) -o $@ $(OBJS)

libpolarssl.dylib: libpolarssl.a
	echo "  LD    $@"
	$(CC) ${LDFLAGS} -dynamiclib -o $@ $(OBJS)

libpolarssl.dll: libpolarssl.a 
	echo "  LD    $@" 
	$(CC) -shared -Wl,-soname,$@ -o $@ $(OBJS) -lws2_32 -lwinmm -lgdi32 

.c.o:
	echo "  CC    $<"
	$(CC) $(CFLAGS) $(OFLAGS) -c $<

clean:
	rm -f *.o libpolarssl.*

