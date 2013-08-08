
DESTDIR=/usr/local
PREFIX=polarssl_

.SILENT:

all:
	cd library  && $(MAKE) all && cd ..
	cd programs && $(MAKE) all && cd ..
#	cd tests && $(MAKE) all && cd ..

clean:
	cd library  && $(MAKE) clean && cd ..
	cd programs && $(MAKE) clean && cd ..
	cd tests && $(MAKE) clean && cd ..
	rm -f polarssl.tar

check:
	( cd tests && $(MAKE) check )

tarball:
	tar --exclude .svn --exclude visualc --exclude tests -cvf polarssl.tar *

