#-------------------------------------------------------------------------------
# Since we are building Hive for multiple architectures we have
# adopted the following standards...
#  Makfile naming format = Makefile.targetOS-architecture
#  
#  Existing Makefiles include:
#
#	Makefile.linux-x86
#	Makefile.solaris-x86
#	Makefile.solaris-sparc
#	Makefile.mikrotik-x86
#	Makefile.mikrotik-mipsbe
#	Makefile.mikrotik-mipsle
#	Makefile.mikrotik-ppc
#
#   Another file named "Makefile" will contain targets for each of
#   these Makefiles.
#
#-------------------------------------------------------------------------------

CLIENT_BASENAME = hive
SERVER_BASENAME = hived

SSL = ../common/ssl
CRYPTO = ../common/crypto
BZIP2 = ../common/bzip2

INCLUDES = -I$(POLARSSL)/include -I../libs
LIBPOLARSSL = $(POLARSSL)/library/libpolarssl.a

.SILENT:

.PHONY: all
all: 
	@echo
	@echo
	@echo " Please specify a supported target:"
	@echo 
	@echo "  make linux-x86"
	@echo "  make linux-x86_64"
	@echo "  make solaris-x86"
	@echo "  make solaris-sparc"
	@echo "  make mikrotik-x86"
	@echo "  make mikrotik-mips"
	@echo "  make mikrotik-mipsel"
	@echo "  make mikrotik-ppc"
	@echo "  make arm"
	@echo
	@echo
	@echo " Administrative tasks, ..."
	@echo "  make clean"
	@echo "  make tarball    ( on Linux machines only)"
	@echo
	@echo

linux-x86: clean
	@make -f Makefile.arch TARGET=linux-x86 

linux-x86_64: clean
	@make -f Makefile.arch TARGET=linux-x86_64

solaris-x86: clean
	@make -f Makefile.arch TARGET=solaris-x86

solaris-sparc: clean
	@make -f Makefile.arch TARGET=solaris-sparc

mikrotik-x86: clean
	@make -f Makefile.arch TARGET=mikrotik-x86

mikrotik-mipsel: clean
	@make -f Makefile.arch TARGET=mikrotik-mipsel

mikrotik-mips: clean
	@make -f Makefile.arch TARGET=mikrotik-mips

mikrotik-ppc: clean
	@make -f Makefile.arch TARGET=mikrotik-ppc

arm: clean
	@make -f Makefile.arch TARGET=arm

.PHONY: clean
CLEAN_LIST = *.o *PATCHED init_strings.* proj_strings* init_crypto_strings.*
CLEAN_LIST += crypto_proj_strings.h crypto_strings_main.h string_utils.h.gch
CLEAN_LIST += mod_hexify.pyc hive.tar

clean:
	@echo
	for file in $(CLEAN_LIST); do \
		echo "\tDeleting\t$$file"; \
		rm -f $$file; \
	done

#	$(MAKE) -C $(SSL) TARGET=clean clean
#	$(MAKE) -C $(POLARSSL)/library clean
#	$(MAKE) -C bzip/bzip2-1.0.6 clean

distclean: clean
	rm -f $(SERVER_BASENAME)-*

tarball: clean
	cd .. && tar --exclude .svn --exclude *.gz --exclude *.tar --exclude *.tgz --exclude documentation/html -cvf hive.tar server
