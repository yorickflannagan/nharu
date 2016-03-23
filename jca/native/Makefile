#
# Makefile inputs for Kiripema Token shared library
# Copyleft (C) 2015 by The Crypthing Initiative
#
# Make parameters:
#	DEBUG=1 or nothing
#	ALIGN=1 or nothing
#
# Required environment (run source kiripema-env)
#
SHELL         = /bin/bash
FILES        := $(shell find . -name '*.c')
CC            = gcc
CXX           = $(CC)

TARGET_NAME    = lib$(NHARU_PRJ)$(JCA_PRJ).so
ifeq ($(DEBUG), 1)
OUTPUT_DIR    = $(NHARU_DIR)/$(JCA_PRJ)/dist/debug
else
OUTPUT_DIR    = $(NHARU_DIR)/$(JCA_PRJ)/dist/release
endif
CFLAGS        = -pedantic-errors -pedantic -Wall -ansi -pthread -Winline -Wunused-parameter
INCLUDES      = -I. -I$(NHARU_DIR)/include -I$(CRYPTOKI) -I$(OPENSSL_INCLUDE) -I$(JAVA_INCLUDE) -I$(JAVA_PLATFORM) -I$(IDN_INCLUDE)
OBJ_FILES     = $(FILES:.c=.o)
VPATH         = .:$(OUTPUT_DIR)
CXXFLAGS      = -shared -shared-libgcc -Xlinker -z -Xlinker defs
IMP_LIBS      = -Wl,-Bstatic -l$(NHARU_PRJ) -lcrypto -lidn -Wl,-Bdynamic -lpthread -ldl
LDLIBS        = -L$(OPENSSL_LIB) -L$(IDN_DIR) -L$(DLA_DIR)

# Debugging
ifeq ($(DEBUG), 1)
CFLAGS       += -ggdb3 -D_DEBUG_ -O0 -save-temps
LDLIBS       += -L$(NHARU_TARGET)/debug
else
CFLAGS       += -O2
LDLIBS       += -L$(NHARU_TARGET)/release
endif

# Struct alignment
ifeq ($(ALIGN), 1)
CFLAGS += -D_ALIGN_
endif

# 64bits compilation
LBITS := $(shell uname -a | grep  x86_64)
ifneq ($(strip $(LBITS)),)
CXXFLAGS   += -fPIC 
CFLAGS     += -fPIC
endif


%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $(OUTPUT_DIR)/$@

$(TARGET_NAME): $(OBJ_FILES)
	cd $(OUTPUT_DIR); \
	$(CXX) $(CXXFLAGS) $(LDLIBS) $(OBJ_FILES) -o $@ $(IMP_LIBS)

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


