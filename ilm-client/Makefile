CLIENT = hclient-$(TARGET)

COMMON = ../common
CRYPTO = $(COMMON)/crypto
SSL = $(COMMON)/ssl

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

library: clean
	@make -f Makefile.arch TARGET=$(TARGET) $@

.PHONY: clean
clean:
	rm -f *.o
	cd $(CRYPTO) && $(MAKE) clean
	cd $(SSL) && $(MAKE) clean

.PHONY: dist-clean
dist-clean:	clean
	@echo
	rm -f $(CLIENT)*
