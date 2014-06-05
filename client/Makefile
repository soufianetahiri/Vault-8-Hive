CLIENT = hclient-$(TARGET)
SSL = ../common/ssl/library
LIBSSL = common/ssl/library/libpolarssl.a
LIBSSL_INCLUDES = common/ssl/include

.SILENT:
.PHONY: all
all: 
	@echo
	@echo " Please specify a supported target:"
	@echo 
	@echo "  make linux-x86"
	@echo "  make linux-x86_64"
	@echo
	@echo " Administrative tasks, ..."
	@echo "  make clean"
	@echo

linux-x86: build
	$(MAKE) -f Makefile.arch TARGET=linux-x86

linux-x86_64: build
	$(MAKE) -f Makefile.arch TARGET=linux-x86_64

library: clean
	$(MAKE) -f Makefile.arch TARGET=$(TARGET) $@

$(LIBSSL):
	cd $(SSL) && $(MAKE) TARGET=$(TARGET)

.PHONY: build
build:
	printf "\n=========================================================================\n"
	printf "        BUILDING CLIENT\n"

.PHONY: clean
clean:
	$(MAKE) -f Makefile.arch clean

.PHONY: dist-clean
distclean:	clean
	@echo
	rm -f $(CLIENT)*
#	rm -f *PATCHED
#	rm -f init_strings.*
#	rm -f proj_strings*
#	rm -f init_crypto_strings.*
#	rm -f crypto_proj_strings.h
#	rm -f crypto_strings_main.h
#	rm -f string_utils.h.gch
#	rm -f mod_hexify.pyc
#	rm -f hive.tar
#	make -C $(POLARSSL)/library clean
#	make -C bzip/bzip2-1.0.6 clean
#	@echo
#	@echo " Done cleaning Hive server."
#	@echo

#distclean: clean
#	rm -f $(CLIENT_BASENAME)-*

#tarball: clean
#	cd .. && tar --exclude .svn --exclude *.gz --exclude *.tar --exclude *.tgz --exclude documentation/html -cvf hive.tar server

.PHONY: patcher
patcher: $(UNPATCHED_BINS) $(LIBSSL) 
	@echo
	@echo "  Latest, unpatched builds of binaries must be"
	@echo "  present with the following naming conventions:"
	@echo "  . hived-solaris-sparc-unpatched"
	@echo "  . hived-solaris-x86-unpatched"
	@echo "  . hived-linux-x86-unpatched"
	@echo "  . hived-mikrotik-x86-unpatched"
	@echo "  . hived-mikrotik-mips-unpatched"
	@echo "  . hived-mikrotik-mipsel-unpatched"
	@echo "  . hived-mikrotik-ppc-unpatched"
	@echo
	xxd -i $(UNPATCHED_SOLARIS_SPARC) _unpatched_solaris_sparc.h
	xxd -i $(UNPATCHED_SOLARIS_X86) _unpatched_solaris_x86.h
	xxd -i $(UNPATCHED_LINUX_X86) _unpatched_linux_x86.h
	xxd -i $(UNPATCHED_MIKROTIK_X86) _unpatched_mikrotik_x86.h
	xxd -i $(UNPATCHED_MIKROTIK_MIPS) _unpatched_mikrotik_mips.h
	xxd -i $(UNPATCHED_MIKROTIK_MIPSEL) _unpatched_mikrotik_mipsel.h
	xxd -i $(UNPATCHED_MIKROTIK_PPC) _unpatched_mikrotik_ppc.h
	gcc -m32 -Os -W -Wall -I. -I$(LIBSSL_INCLUDES) string_utils.c patcher.c -o hive-patcher $(LIBSSL)
	strip hive-patcher
	md5sum hive-patcher > hive-patcher.md5
#
#.PHONY: clean
#clean:
#	rm -f ${BINARY}* ${BINARY}-dbg* *.o *.a init_strings.c core cryptcat/*.o cryptcat/cryptcat
##	rm -f _unpatched_solaris_sparc.h _unpatched_windows_i386.h _unpatched_linux_i386.h
#	rm -f _unpatched_*.h
#	rm -f hive-patcher hive-patcher.md5 *PATCHED *PATCHED.exe
#	rm -f *UNpatched*
#	rm -f init_strings.*
#	rm -f init_crypto_strings.*
#	rm -f string_utils.o
#	rm -f crypto_strings_main.h
#	rm -f string_utils.h.*
#	rm -f crypto_proj_strings.h
#	rm -f mod_hexify.pyc
#	rm -f proj_strings_main.h
#	rm -f proj_strings.h
#	make -C $(POLARSSL)/library clean
