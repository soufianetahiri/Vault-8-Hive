
#------------------------------------------------------------------------------------
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
#   Another file named "Makefile" will contain targets for each of these Makefiles.
#
#------------------------------------------------------------------------------------

OFLAGS	= -Os

# MicroBlaze specific options:
# CFLAGS += -mno-xl-soft-mul -mxl-barrel-shift

# To compile on Plan9:
# CFLAGS += -D_BSD_EXTENSION

# To compile as a shared library:
# CFLAGS += -fPIC

DLEXT=so
# OSX shared library extension:
# DLEXT=dylib

OBJS=	aes.o		arc4.o		base64.o	\
	bignum.o	certs.o		debug.o		\
	des.o		dhm.o		havege.o	\
	md2.o		md4.o		md5.o		\
	net.o		padlock.o	rsa.o		\
	sha1.o		sha2.o		sha4.o		\
	ssl_cli.o	ssl_srv.o	ssl_tls.o	\
	timing.o	x509parse.o	xtea.o		\
	camellia.o  version.o	loki_utils.o

.SILENT:

#Added clean to prevent architecture conflicts with libraries
.PHONY : all
all: clean            
	@echo
	@echo
	@echo " Please specify a support target:"
	@echo 
	@echo "  make linux-x86"
	@echo "  make solaris-x86"
	@echo "  make solaris-sparc"
	@echo "  make mikrotik-x86"
	@echo "  make mikrotik-mipsbe"
	@echo "  make mikrotik-mipsle"
	@echo "  make mikrotik-ppc"
	@echo
	@echo
	@echo " Administrative tasks:"
	@echo "  make clean"
	@echo "  make svnclean"
	@echo "  make tarball    ( on linux machines only)"
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

svnclean: clean

clean:
	rm -f *.o libpolarssl.*
	@echo "Executed PolarSSL library's Makefile clean..."

tarball:
	tar --exclude .svn -cvf libpolarssl.tar *
	@echo "Executed PolarSSL library's Makefile tarball..."


