CLIENT = hclient-$(TARGET)
SSL = ../common/ssl/library
LIBSSL = common/ssl/library/libpolarssl.a
LIBSSL_INCLUDES = common/ssl/include

UNPATCHED_SOLARIS_SPARC = hived-solaris-sparc-unpatched
UNPATCHED_SOLARIS_X86 = hived-solaris-x86-unpatched
UNPATCHED_LINUX_X86 = hived-linux-x86-unpatched
UNPATCHED_MIKROTIK_X86 = hived-mikrotik-x86-unpatched
UNPATCHED_MIKROTIK_MIPS = hived-mikrotik-mips-unpatched
UNPATCHED_MIKROTIK_MIPSEL = hived-mikrotik-mipsel-unpatched
UNPATCHED_MIKROTIK_PPC = hived-mikrotik-ppc-unpatched

UNPATCHED_BINS = $(UNPATCHED_SOLARIS_SPARC) $(UNPATCHED_LINUX_X86)
UNPATCHED_BINS += $(UNPATCHED_SOLARIS_X86) $(UNPATCHED_MIKROTIK_X86) $(UNPATCHED_MIKROTIK_MIPS)
UNPATCHED_BINS += $(UNPATCHED_MIKROTIK_PPC) $(UNPATCHED_MIKROTIK_MIPSEL)

.SILENT:
.PHONY: all
all: 
	printf "\n\tPlease specify a supported target:\n"
	printf "\n\t\tmake linux-x86\n"
	printf "\t\tmake linux-x86_64\n"
	printf "\n\tTo make the patcher use:\n"
	printf "\n\t\tmake linux-x86 patcher\n"
	printf "\n\t\tNOTE: make will produce an error if all binaries are not present.\n"
	printf "\n\tAdministrative tasks, ...\n"
	printf "\t\tmake clean\n"
	printf "\t\tmake distclean\n"

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

#.PHONY: clean
#clean:
#	$(MAKE) -f Makefile.arch clean

.PHONY: distclean
distclean:	clean
	printf "\tDIST CLEANING:\t$(CURDIR)\n"
	rm -f $(CLIENT)*

.PHONY: tarball
tarball: clean
	printf "\n\tCreating tarball of $(CURDIR)\n"
	cd .. && \
	tar --exclude .svn --exclude *.gz --exclude *.tar --exclude *.tgz --exclude documentation/html -cvf hive-client.tar client 1>/dev/null

.PHONY: clean
clean:
	printf "\n\tCLEANING:\t$(CURDIR)\n"
	rm -f *.o *.a init_strings.c core cryptcat/*.o cryptcat/cryptcat
	rm -f _unpatched_*.h
	rm -f hive-patcher hive-patcher.md5 *PATCHED *PATCHED.exe
	rm -f *UNpatched*
	rm -f init_strings.*
	rm -f init_crypto_strings.*
	rm -f string_utils.o
	rm -f crypto_strings_main.h
	rm -f string_utils.h.*
	rm -f crypto_proj_strings.h
	rm -f mod_hexify.pyc
	rm -f proj_strings_main.h
	rm -f proj_strings.h
	$(MAKE) -C $(SSL) clean
