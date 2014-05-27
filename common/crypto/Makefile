####################################################
# Architecture-agnostic Makefile for Hive crypto
####################################################

# Defaults
CFLAGS	= -Wall -W -Wdeclaration-after-statement
OFLAGS	= -O2
COMMON = ..
SSL = $(COMMON)/ssl
INCLUDES = -I.. -I$(SSL)/include

.PHONY: ARCH_BUILD
include ARCH_BUILD

ifeq ("$(TARGET)", "")
  $(info .)
  $(info .  TARGET not specified)
  $(info .  Use "make TARGET=<target O/S-architecture>".)
  $(info .  For a list of valid targets, run "make" in the client or server directory.)
  $(info .)
  $(error .)
else ifeq ("$(TARGET)", "linux-x86")
  include ../Makefile-include.linux-x86
else ifeq ("$(TARGET)", "linux-x86_64")
  include ../Makefile-include.linux-x86_64
else ifeq ("$(TARGET)", "mikrotik-mips")
  include ../Makefile-include.mikrotik-mips
else ifeq ("$(TARGET)", "mikrotik-mipsel")
  include ../Makefile-include.mikrotik-mipsel
else ifeq ("$(TARGET)", "mikrotik-x86")
  include ../Makefile-include.mikrotik-x86
else ifeq ("$(TARGET)", "mikrotik-ppc")
  include ../Makefile-include.mikrotik-ppc
else ifeq ("$(TARGET)", "arm")
  include ../Makefile-include.arm
else ifeq ("$(TARGET)", "solaris-sparc")
  include ../Makefile-include.solaris-sparc
else ifeq ("$(TARGET)", "solaris-x86")
  include ../Makefile-include.solaris-x86
else
  $(info .)
  $(info .  Invalid target "$(TARGET)")
  $(info .  Run "make" in client or server directory for a list of valid targets.)
  $(info .)
  $(error .)
endif

ifdef DEBUG
CFLAGS += -g3
endif

##########################################################################
AR = ar

LIBCRYPTO = libcrypto.a

LDFLAGS = -lpthread -lutil

CRYPTO_OBJS = crypto.o init_crypto_strings.o loki_utils.o

PS = process_list.c
NETSTAT = netstat_an.c netstat_rn.c
IFC = ifconfig.c

CFLAGS += $(INCLUDES)

DBGFLAGS += -DDEBUG -D_DEBUG -g

STRIPFLAGS += --strip-all --remove-section=.comment --remove-section=.note

.SILENT:
.PHONY: $(CRYPTO_BUILD_OPTS)
.PHONY: all

$(info )
$(info )
$(info =========================================================================)
ifdef ARCH_BUILD_CRYPTO
  ifneq ("$(ARCH_BUILD_CRYPTO)", "$(TARGET)")
    $(info .  Rebuilding libcrypto for $(TARGET))
    CRYPTO_BUILD_OPTS:=clean
  else
    CRYPTO_BUILD_OPTS:=
    $(info .  libcrypto for $(TARGET) previously built.)
  endif
else
  CRYPTO_BUILD_OPTS:=clean
  $(info .  Building libcrypto for $(TARGET))
endif

$(info =========================================================================)
$(info TARGET: $(TARGET))
$(info SRCDIR: $(PWD))
$(info CFLAGS: $(CFLAGS))
$(info =========================================================================)
$(info )

$(LIBCRYPTO): $(CRYPTO_BUILD_OPTS) $(CRYPTO_OBJS) crypto_strings
	@echo "   AR    $@"
	$(AR) r $@ $(CRYPTO_OBJS)
	@echo "   RL    $@"
	@$(AR) s $@
	echo "ARCH_BUILD_CRYPTO=$(TARGET)" > ARCH_BUILD

.PHONY: crypto_strings

crypto_strings: init_crypto_strings.o 
init_crypto_strings.o: init_crypto_strings.c 
init_crypto_strings.c: crypto_strings.txt 
	python mod_gen_cryptostring_header.py crypto_strings.txt CRYPTO_STRINGS

.PHONY: clean
clean:
	rm -f $(LIBCRYPTO) $(CRYPTO_OBJS)
	rm -f init_crypto_strings.*

.c.o:
#	echo -en "\tCC\t$<"
	echo "   CC        $<"
	$(CC) $(CFLAGS) -c $<
