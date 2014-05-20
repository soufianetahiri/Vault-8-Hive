CLIENT = hclient-$(TARGET)

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

linux-x86: clean
	@make -f Makefile.arch TARGET=linux-x86 

linux-x86_64: clean
	@make -f Makefile.arch TARGET=linux-x86_64

.PHONY: clean
clean:
	@echo
	rm -f *.o 

.PHONY: dist-clean
dist-clean:	clean
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

#.PHONY: patcher
#patcher: $(UNPATCHED_BINS) $(LIBPOLARSSL) 
#	@echo
#	@echo "  Latest, unpatched builds of binaries must be"
#	@echo "  present with the following naming conventions:"
##	@echo "  . hived-windows-i386-unpatched.exe"
#	@echo "  . hived-solaris-sparc-unpatched"
#	@echo "  . hived-solaris-i386-unpatched"
#	@echo "  . hived-linux-i386-unpatched"
#	@echo "  . hived-mikrotik-i386-unpatched"
#	@echo "  . hived-mikrotik-mipsbe-unpatched"
#	@echo "  . hived-mikrotik-mipsle-unpatched"
#	@echo "  . hived-mikrotik-ppc-unpatched"
#	@echo
##	xxd -i $(UNPATCHED_WINDOWS_I386) _unpatched_windows_i386.h
#	xxd -i $(UNPATCHED_SOLARIS_SPARC) _unpatched_solaris_sparc.h
#	xxd -i $(UNPATCHED_SOLARIS_I386) _unpatched_solaris_i386.h
#	xxd -i $(UNPATCHED_LINUX_I386) _unpatched_linux_i386.h
#	xxd -i $(UNPATCHED_MIKROTIK_I386) _unpatched_mikrotik_i386.h
#	xxd -i $(UNPATCHED_MIKROTIK_MIPSBE) _unpatched_mikrotik_mipsbe.h
#	xxd -i $(UNPATCHED_MIKROTIK_MIPSLE) _unpatched_mikrotik_mipsle.h
#	xxd -i $(UNPATCHED_MIKROTIK_PPC) _unpatched_mikrotik_ppc.h
#	gcc -m32 -Os -W -Wall -I. -I./ssl/polarssl/include/polarssl string_utils.c patcher.c -o hive-patcher $(LIBPOLARSSL)
#	strip hive-patcher
#	md5sum hive-patcher > hive-patcher.md5
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
#
#.PHONY: svnclean
#svnclean:
#	rm -f *.o init_strings.c core
#	rm -f _unpatched_*.h
##	rm -f _unpatched_solaris_sparc.h _unpatched_windows_i386.h _unpatched_linux_i386.h
##	rm -f _unpatched_solaris_i386.h _unpatched_mikrotik_i386.h
#	rm -f *PATCHED *PATCHED.exe
#	rm -f *UNpatched*
#	rm -f crypto_strings_main.h
#	rm -f init_crypto_strings.c
#	rm -f crypto_proj_strings.h
#	rm -f string_utils.h.gch
#	rm -f mod_hexify.pyc
