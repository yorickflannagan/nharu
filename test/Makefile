#
# Makefile for Nharu test application
# Copyleft (C) 2015 by The Crypthing Initiative
#
# Required environment (run source kiripema-env)
#	NTEST_PRJ: test application name
#	TEST_TARGET: app distribution directory
#	NHARU_DIR: Nharu project directory
#	OPENSSL_INCLUDE: OpenSSl include files directory
#	CRYPTOKI: pkcs#11 include files directory
#	NHARU_PRJ: Nharu library
#	NHARU_TARGET: Nharu library distribution directory
#	OPENSSL_LIB: OpenSSL static libraries directory
#	DLA_DIR: libdl.so library directory
#

SHELL         = /bin/sh
FILES        := $(shell find . -name '*.c')
CC            = gcc
CXX           = $(CC)

TARGET_NAME    = $(NTEST_PRJ)
OUTPUT_DIR    = $(TEST_TARGET)/debug
CFLAGS        = -pedantic-errors -pedantic -Wall -ansi -ggdb3 -D_DEBUG_ -O0 -save-temps
INCLUDES      = -I. -I$(NHARU_DIR)/include -I$(OPENSSL_INCLUDE) -I$(CRYPTOKI) -I$(IDN_INCLUDE)
OBJ_FILES     = $(FILES:.c=.o)
VPATH         = .:$(OUTPUT_DIR)
CXXFLAGS      = 
IMP_LIBS      = -Wl,-Bstatic -l$(NHARU_PRJ) -lcrypto -lidn -Wl,-Bdynamic -lpthread -ldl
LDLIBS        = -L$(NHARU_TARGET)/debug -L$(OPENSSL_LIB) -L$(IDN_DIR) -L$(DLA_DIR)

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


