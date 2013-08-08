
# the Hive project does not use this file
# the Hive project jumps directly to the Makefiles in the ./library/ directory
DESTDIR=/usr/local
PREFIX=polarssl_

.SILENT:

.PHONY: all
all: clean
	@echo
	@echo "Ignoring the 'programs' and 'test' directories since they are not needed for hive, only the library is needed. Enter 'cd library' and then"
	cd library  && $(MAKE) all && cd ..
	@echo
#	@echo "The 'programs' and 'test' directories do not compile correctly right now anyways..." 
#	@echo
#	cd programs && $(MAKE) all && cd ..
#	cd tests && $(MAKE) all && cd ..

.PHONY: clean
clean:
	cd library  && $(MAKE) clean && cd ..
	cd programs && $(MAKE) clean && cd ..
	cd tests && $(MAKE) clean && cd ..
	rm -f polarssl.tar

#check:
#	( cd tests && $(MAKE) check )

tarball:
	tar --exclude .svn --exclude visualc --exclude tests -cvf polarssl.tar *

