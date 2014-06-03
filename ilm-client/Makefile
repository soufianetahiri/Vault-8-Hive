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

library: clean
	@make -f Makefile.arch TARGET=$(TARGET) $@

.PHONY: clean
clean:
	@echo
	rm -f *.o 

.PHONY: dist-clean
dist-clean:	clean
	@echo
	rm -f $(CLIENT)*
