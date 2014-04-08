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

POLARSSL = polarssl
INCLUDES = -I$(POLARSSL)/include -I../libs
LIBPOLARSSL = $(POLARSSL)/library/libpolarssl.a

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
	@echo "  make svnclean"
	@echo "  make tarball    ( on Linux machines only)"
	@echo
	@echo

linux-x86: clean
	@make -f Makefile.linux-x86

linux-x86_64: clean
	@make -f Makefile.linux-x86_64

solaris-x86: clean
	@make -f Makefile.solaris-x86

solaris-sparc: clean
	@make -f Makefile.solaris-sparc

mikrotik-x86: clean
	@make -f Makefile.mikrotik-x86

mikrotik-mipsel: clean
	@make -f Makefile.mikrotik-mipsel

mikrotik-mips: clean
	@make -f Makefile.mikrotik-mips

mikrotik-ppc: clean
	@make -f Makefile.mikrotik-ppc

arm: clean
	@make -f Makefile.arm

.PHONY: clean-objects
clean-objects:
	@echo
	rm -f *.o 
	rm -f hive.tar

.PHONY: clean
clean:
	@echo
	rm -f *.o 
	rm -f *PATCHED
#	rm -f $(SERVER_BASENAME)-*
	rm -f init_strings.*
	rm -f proj_strings*
	rm -f init_crypto_strings.*
	rm -f crypto_proj_strings.h
	rm -f crypto_strings_main.h
	rm -f string_utils.h.gch
	rm -f mod_hexify.pyc
	rm -f hive.tar
	make -C $(POLARSSL)/library clean
	make -C bzip/bzip2-1.0.6 clean
	@echo
	@echo " Done cleaning Hive server."
	@echo

svnclean: clean

tarball: clean
	cd .. && tar --exclude .svn --exclude *.gz --exclude *.tar --exclude *.tgz --exclude documentation/html -cvf hive.tar server
