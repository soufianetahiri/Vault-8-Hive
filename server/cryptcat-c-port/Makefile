OUTFILE = jshell
POLARSSL = ../../libs/polarssl-0.14.0

.PHONY: all
all: 
	@echo
	@echo
	@echo " Please specify a supported target:"
	@echo 
	@echo "  make linux-x86 "
	@echo "  make solaris-x86"
	@echo "  make solaris-sparc"
	@echo "  make mikrotik-x86"
	@echo "  make mikrotik-mipsbe"
	@echo "  make mikrotik-mipsle"
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

linux-x86:
	@make -f Makefile.linux-x86

solaris-x86:
	@make -f Makefile.solaris-x86

solaris-sparc:
	@make -f Makefile.solaris-sparc

mikrotik-x86:
	@make -f Makefile.mikrotik-x86

mikrotik-mipsle:
	@make -f Makefile.mikrotik-mipsle

mikrotik-mipsbe:
	@make -f Makefile.mikrotik-mipsbe

mikrotik-ppc:
	@make -f Makefile.mikrotik-ppc

arm:
	@make -f Makefile.arm

.PHONY: clean
clean:
	rm -f $(OUTFILE) $(OUTFILE)-dbg *.o *.obj *.tar *.gz *.tgz
	make -C $(POLARSSL)/library clean

svnclean: clean

tarball: clean
	cd ../.. && tar --exclude .svn --exclude *.gz --exclude *.tar --exclude *.tgz -cvf server/cryptcat-c-port/cryptcat-c.tar server/ libs/
