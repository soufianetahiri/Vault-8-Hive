# Also see "include/polarssl/config.h"
LIBDIR = .
#CFLAGS	= -I../.. -I../include -Wall -W -Wdeclaration-after-statement
#OFLAGS	= -O2
.PHONY: ARCH_BUILD
include ARCH_BUILD

ifdef ARCH_BUILD_SSL
  ifneq ("$(ARCH_BUILD_SSL)", "$(TARGET)")
    $(info .)
    $(info .  Rebuilding SSL library for $(TARGET))
    $(info .)
    SSL_BUILD_OPTS:=clean
  else
    SSL_BUILD_OPTS:=
    $(info .)
    $(info .  SSL library for $(TARGET) previously built.)
    $(info .)
  endif
else
  SSL_BUILD_OPTS:=clean
  $(info .)
  $(info .  Building SSL library for $(TARGET))
  $(info .)
endif


ifeq ("$(TARGET)", "linux-x86")
  include ../../Makefile-include.linux-x86
else ifeq ("$(TARGET)", "linux-x86_64")
  include ../../Makefile-include.linux-x86_64
else ifeq ("$(TARGET)", "mikrotik-mips")
  include ../../Makefile-include.mikrotik-mips
else ifeq ("$(TARGET)", "mikrotik-mipsel")
  include ../../Makefile-include.mikrotik-mipsel
else ifeq ("$(TARGET)", "mikrotik-x86")
  include ../../Makefile-include.mikrotik-x86
else ifeq ("$(TARGET)", "mikrotik-ppc")
  include ../../Makefile-include.mikrotik-ppc
else ifeq ("$(TARGET)", "arm")
  include ../../Makefile-include.arm
else ifeq ("$(TARGET)", "solaris-sparc")
  includtorm
 ../../Makefile-include.solaris-sparc
else ifeq ("$(TARGET)", "solaris-x86")
  include ../../Makefile-include.solaris-x86
else
  $(error Invalid target "$(TARGET)")
endif

CFLAGS += -I../../crypto -I../include -I../ssl/include

ifdef DEBUG@

CFLAGS += -g3
CFLAGS += -DPOLARSSL_DEBUG_C -DPOLARSSL_DEBUG_MSG
endif

$(info )
$(info =================================================)
$(info TARGET: $(TARGET))
$(info SRCDIR: $(PWD))
$(info CFLAGS: $(CFLAGS))
$(info =================================================)
$(info )

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
		x509parse.o	xtea.o
	

.SILENT:
.PHONY: $(SSL_BUILD_OPTS)

all: static

static: $(LIBDIR)/libpolarssl.a

shared: $(LIBDIR)/libpolarssl.$(DLEXT)

$(LIBDIR)/libpolarssl.a: $(SSL_BUILD_OPTS) $(OBJS)
	echo "  AR    $@"
	$(AR) r $@ $(OBJS)
	echo "  RL    $@"
	$(AR) s $@
	echo "ARCH_BUILD_SSL=$(TARGET)" > ARCH_BUILD

$(LIBDIR)/libpolarssl.so: libpolarssl.a
	echo "  LD    $@"
	$(CC) ${LDFLAGS} -shared -Wl,-soname,$(SONAME) -o $@ $(OBJS)

$(LIBDIR)/libpolarssl.dylib: libpolarssl.a
	echo "  LD    $@"
	$(CC) ${LDFLAGS} -dynamiclib -o $@ $(OBJS)

$(LIBDIR)/libpolarssl.dll: libpolarssl.a 
	echo "  LD    $@" 
	$(CC) -shared -Wl,-soname,$@ -o $@ $(OBJS) -lws2_32 -lwinmm -lgdi32 

.c.o:
	echo "  CC    $<"
	$(CC) $(CFLAGS) $(OFLAGS) -c $<

clean:
	rm -f *.o libpolarssl.*
	>ARCH_BUILD
