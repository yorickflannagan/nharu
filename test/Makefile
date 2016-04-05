#
# Makefile for Nharu test application
# Copyleft (C) 2015 by The Crypthing Initiative
#
# Required environment (run source kiripema-env)
#	OPENSSL_INCLUDE: OpenSSl include files directory
#	IDN_INCLUDE: GNU Libidn include files directory
#	OPENSSL_LIB: OpenSSL static library location
#	IDN_DIR: Libdn static library location
#	DLA_DIR: GNU development library location
#

SHELL         = /bin/sh
FILES        := $(shell find . -name '*.c')
CC            = gcc
CXX           = $(CC)

TARGET_NAME    = ntest-app
OUTPUT_DIR    = ../bin
CFLAGS        = -pedantic-errors -pedantic -Wall -ansi -ggdb3 -D_DEBUG_ -O0 -save-temps
INCLUDES      = -I. -I../include -I../pkcs11 -I$(OPENSSL_INCLUDE) -I$(IDN_INCLUDE)
OBJ_FILES     = $(FILES:.c=.o)
VPATH         = .:$(OUTPUT_DIR)
CXXFLAGS      = 
IMP_LIBS      = -Wl,-Bstatic -lnharu -lcrypto -lidn -Wl,-Bdynamic -lpthread -ldl
LDLIBS        = -L../libs -L$(OPENSSL_LIB) -L$(IDN_DIR) -L$(DLA_DIR)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $(OUTPUT_DIR)/$@

$(TARGET_NAME): $(OBJ_FILES)
	cd $(OUTPUT_DIR); \
	$(CXX) $(CXXFLAGS) $(LDLIBS) $(OBJ_FILES) -o $@ $(IMP_LIBS)

.PHONY: clean donothing
clean:
	find $(OUTPUT_DIR) -type f -regex ".*\.\(so\|o\|a\|i\|d\|s\)" -exec rm -f {} \;
	find . -type f -regex ".*\.\(so\|o\|a\|i\|d\|s\)" -exec rm -f {}             \;
	rm -f $(OUTPUT_DIR)/*

donothing:
	@echo $(NTEST_PRJ) has nothing to do...

files.d: $(FILES)
	cat /dev/null > files.d;                         \
	for i in $(FILES); do                            \
		$(CC) -MM $$i $(INCLUDES) >> files.d;      \
	done;                                            \
	touch -m ./files.d


include ./files.d


