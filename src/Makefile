#
# Makefile Nharu static library
# Copyleft (C) 2015 by The Crypthing Initiative
#
# Make parameters:
#	DEBUG=1 or nothing
#	ALIGN=1 or nothing
#
# Required environment (run source nharu-env)
#	OPENSSL_INCLUDE: OpenSSl include files directory
#	IDN_INCLUDE: GNU Libidn include files directory
#

SHELL         = /bin/bash
FILES        := $(shell find . -name '*.c')
CC            = gcc
AR            = ar


TARGET_NAME   = libnharu.a
OUTPUT_DIR    = ../libs
CFLAGS        = -pedantic-errors -pedantic -Wall -ansi -pthread -Winline -Wunused-parameter
INCLUDES      = -I. -I../include -I../pkcs11 -I$(OPENSSL_INCLUDE) -I$(IDN_INCLUDE)
OBJ_FILES     = $(FILES:.c=.o)
VPATH         = .:$(OUTPUT_DIR)
ARFLAGS       = -r -s

# Debugging
ifeq ($(DEBUG), 1)
CFLAGS       += -ggdb3 -D_DEBUG_ -O0 -save-temps
else
CFLAGS       += -O2
endif

# Struct alignment
ifeq ($(ALIGN), 1)
CFLAGS += -D_ALIGN_
endif

# 64bits compilation
LBITS := $(shell uname -a | grep  x86_64)
ifneq ($(strip $(LBITS)),)
CFLAGS     += -fPIC
endif


%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $(OUTPUT_DIR)/$@

$(TARGET_NAME): $(OBJ_FILES)
	cd $(OUTPUT_DIR); \
	$(AR) $(ARFLAGS) $@ $(OBJ_FILES)

.PHONY: clean
clean:
	find $(OUTPUT_DIR) -type f -regex ".*\.\(so\|o\|a\|i\|d\|s\)" -exec rm -f {} \;
	find . -type f -regex ".*\.\(so\|o\|a\|i\|d\|s\)" -exec rm -f {}             \;


files.d: $(FILES)
	cat /dev/null > files.d;                         \
	for i in $(FILES); do                            \
		$(CC) -MM $$i $(INCLUDES) >> files.d;      \
	done;                                            \
	touch -m ./files.d

include ./files.d


