
POLARSSL = ../client/ssl/polarssl
LIBHCLIENT = ../client/libhclient.a
LIBCRYPTCAT = ../client/libcryptcat.a
LIBPOLARSSL = $(POLARSSL)/library/libpolarssl.a
HCLIENT = ./hclient-linux

INCLUDES += -I.
INCLUDES += -I../client
INCLUDES += -I../client/cryptcat
INCLUDES += -I$(POLARSSL)/include
INCLUDES += -I../libs 
INCLUDES += -I include

#LIBS=$(LIBCRYPTCAT) $(LIBHCLIENT) libILM_SDK.a $(LIBPOLARSSL)
LIBS=$(LIBHCLIENT) libILM_SDK.a $(LIBPOLARSSL)
SRC += Command.cpp
SRC += File.cpp
SRC += Ilm.cpp
SRC += Connection.cpp
SRC += Utilities.cpp
SRC += hive.cpp $(LIBS)
OUTFILE=hive
#CFLAGS=-fPIC -shared -Wall -lpthread
CFLAGS=-fPIC -Wall -Werror -Wextra -lpthread -lc -ansi

# building hclient will build the requisite PolarSSL libraries. This could be done directly
.PHONY: all
all: cryptcat $(LIBPOLARSSL) $(LIBHCLIENT) $(HCLIENT)
	+ g++ $(CFLAGS) -shared $(INCLUDES) $(SRC) -o $(OUTFILE)
	md5sum $(OUTFILE) > $(OUTFILE).md5
	rm -f cryptcat.h

$(LIBPOLARSSL):
	cd $(POLARSSL)/library && $(MAKE) -f Makefile.linux-x86

$(HCLIENT):
	cd ../client && $(MAKE) release 
	cp ../client/$(HCLIENT) .

libhclient: $(LIBHCLIENT)

$(LIBHCLIENT):
	cd ../client && $(MAKE) library

libcryptcat: $(LIBCRYPTCAT)

$(LIBCRYPTCAT):
	cd ../client && $(MAKE) libcryptcat

.PHONY: cryptcat
cryptcat:
	cd ../client/cryptcat && make linux
	xxd -i ../client/cryptcat/cryptcat cryptcat.h

.PHONY: test
test:
	g++ $(CFLAGS) $(INCLUDES) -c hive.cpp
	g++ $(CFLAGS) $(INCLUDES) -c GenRandomBytes.cpp
	g++ $(CFLAGS) $(INCLUDES) -c TxCommand.cpp
	g++ $(CFLAGS) $(INCLUDES) -c ListenHandler.cpp
	g++ $(CFLAGS) -shared $(INCLUDES) *.o $(LIBS) -o $(OUTFILE)
#	g++ $(CFLAGS) -I $(INCLUDES) -L $(LPATH) -l $(LIB) $(SRC) -o $(OUTFILE)

.PHONY: clean
clean:
	rm -f *.o $(OUTFILE) ../client/cryptcat/cryptcat cryptcat.h
	rm -f $(LIBHCLIENT)
	rm -f $(LIBCRYPTCAT)
	rm -f hclient-linux-dbg
	rm -f $(OUTFILE).md5
	make -C $(POLARSSL)/library clean
	make -C ../client clean

