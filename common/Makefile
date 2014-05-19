#------------------------------------------------
#Makefile for compiling Linux
# Makefile.linux-x86
#
# For other possible targets, please enter:
#	
#		make all
#
#------------------------------------------------

# Defaults
CFLAGS	= -Wall -W -Wdeclaration-after-statement
OFLAGS	= -O2

ifeq ("$(TARGET)", "linux-x86")
	include Makefile-include.linux-x86
endif
ifeq ("$(TARGET)", "linux-x86_64")
	include Makefile-include.linux-x86_64
endif
ifeq ("$(TARGET)", "mikrotik-mips")
	include Makefile-include.mikrotik-mips
endif
ifeq ("$(TARGET)", "mikrotik-mipsel")
	include Makefile-include.mikrotik-mipsel
endif
ifeq ("$(TARGET)", "mikrotik-x86")
	include Makefile-include.mikrotik-x86
endif
ifeq ("$(TARGET)", "mikrotik-ppc")
	include Makefile-include.mikrotik-ppc
endif
ifeq ("$(TARGET)", "arm")
	include Makefile-include.arm
endif
ifeq ("$(TARGET)", "solaris-sparc")
	include Makefile-include.solaris-sparc
endif
ifeq ("$(TARGET)", "solaris-x86")
	include Makefile-include.solaris-x86
endif

ifdef DEBUG
CFLAGS += -g3
CFLAGS += -DPOLARSSL_DEBUG_C -DPOLARSSL_DEBUG_MSG
endif

##########################################################################
AR = ar
BIN = .
LIB = .

CLIENT_BASENAME = hive
SERVER_BASENAME = hived

SSL = polarssl
BZIP2 = bzip2
INCLUDES = -I$(SSL)/include -I$(BZIP2) -I../.. -I.
LIBSSL = $(SSL)/library/libpolarssl.a
LIBBZIP2 = $(BZIP2)/libbz2.a
LIBCRYPTO = libcrypto.a

LDFLAGS = -lpthread -lutil

CRYPTO_OBJS = crypto.o init_crypto_strings.o loki_utils.o

PS = process_list.c
NETSTAT = netstat_an.c netstat_rn.c
IFC = ifconfig.c

CFLAGS += $(INCLUDES)

DBGFLAGS += -DDEBUG -D_DEBUG -g

STRIPFLAGS += --strip-all --remove-section=.comment --remove-section=.note

OS = $(shell uname)

ifeq ($(OS),Linux)
#ARCH = $(shell uname -m)
ARCH=x86
SERVER = $(SERVER_BASENAME)-$(TARGET)
endif

.PHONY: all
all: $(LIBSSL) $(BZIP2) $(LIBCRYPTO)

$(LIBSSL): crypto_strings
	cd $(SSL)/library && $(MAKE) TARGET=$(TARGET)

bzip2:	$(LIBBZIP2)

$(LIBBZIP2):
#	cd $(BZIP2) && $(MAKE) -f Makefile.$(TARGET) libbz2.a
	cd $(BZIP2) && $(MAKE) TARGET=$(TARGET) libbz2.a

$(LIBCRYPTO): $(CRYPTO_OBJS)
	@echo "  AR    $@"
	$(AR) r $@ $(CRYPTO_OBJS)
	@echo "  RL    $@"
	@$(AR) s $@

.PHONY: crypto_strings

crypto_strings: init_crypto_strings.o 
init_crypto_strings.o: init_crypto_strings.c 
init_crypto_strings.c: crypto_strings.txt 
	python mod_gen_cryptostring_header.py crypto_strings.txt CRYPTO_STRINGS

.PHONY: clean
clean:
	(cd $(SSL) && make clean)
	(cd $(BZIP2) && make clean)
	rm -f $(LIBCRYPTO) $(CRYPTO_OBJS)
	rm -f init_crypto_strings.*
	
