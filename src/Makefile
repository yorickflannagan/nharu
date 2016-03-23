#
# Makefile inputs for Nharu static library
# Copyleft (C) 2015 by The Crypthing Initiative
#
# Make parameters:
#	DEBUG=1 or nothing
#	ALIGN=1 or nothing
#
# Required environment (run source kiripema-env)
#	NHARU_PRJ: library name
#	NHARU_TARGET: distribution library
#	NHARU_DIR: project location
#	CRYPTOKI: pkcs#11 include files directory
#	OPENSSL_INCLUDE: OpenSSl include files directory
#

SHELL         = /bin/bash
FILES        := $(shell find . -name '*.c')
CC            = gcc
AR            = ar


TARGET_NAME   = lib$(NHARU_PRJ).a
ifeq ($(DEBUG), 1)
OUTPUT_DIR    = $(NHARU_TARGET)/debug
else
OUTPUT_DIR    = $(NHARU_TARGET)/release
endif
CFLAGS        = -pedantic-errors -pedantic -Wall -ansi -pthread -Winline -Wunused-parameter
INCLUDES      = -I. -I$(NHARU_DIR)/include -I$(CRYPTOKI) -I$(OPENSSL_INCLUDE) -I$(IDN_INCLUDE)
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


