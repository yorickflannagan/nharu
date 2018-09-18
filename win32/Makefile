# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
# Windows makefile for Nharu project
# Copyleft (C) 2016 by The Crypthing Initiative
# Authors:
#	diego.sohsten@caixa.gov.br
# 	yorick.flannagan@gmail.com
#
# Required environment
#	PROJECT_HOME: Nharu directory (cloned from Git)
#	OPENSSL: OpenSSL library install directory
#	LIBIDN: GNU Libidn library install directory
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
CC                 = cl
LINK               = link
IMPLIB             = lib
MC                 = mc
RC                 = rc

TARGET             =
TARGET_CVARS       =
TARGET_CFLAGS      =
TARGET_LIB_CFLAGS  =
TARGE_TEST_CFLAGS  =
TARGET_LFLAGS      =
TARGET_LIB_LFLAGS  =
TARGET_TEST_LFLAGS =

PROJECT_HOME       = $(USERPROFILE)\dev\nharu
OPENSSL            = $(OPENSSL)
LIBIDN             = $(LIBIDN)
JAVA_HOME          = $(JAVA_HOME)

OBJ_FILES          = $(PROJECT_HOME)\bin\$(TARGET)
OUT_FILES          = $(PROJECT_HOME)\dist\$(TARGET)
PKCS_FILES         = $(PROJECT_HOME)\pkcs11
LIB_FILES          = $(PROJECT_HOME)\src
TEST_FILES         = $(PROJECT_HOME)\test
JCA_FILES          = $(PROJECT_HOME)\jca\native

!IF DEFINED(DEBUG)
!include <debug.mak>
!ELSE
!include <release.mak>
!ENDIF

COMMON_CVARS       = /D "WIN32" /D "_WIN32" /D "_UNICODE" /D "UNICODE"
COMMON_CFLAGS      = /c /permissive- /GS /TC /analyze- /W3 /Zc:wchar_t /Zi /Gm- /sdl /Zc:inline /fp:precise /errorReport:prompt \
					/WX- /Zc:forScope /Gd /Oy- /FC /nologo /diagnostics:classic
COMMON_LFLAGS      = /NXCOMPAT /DYNAMICBASE /MACHINE:X86 /INCREMENTAL:NO /ERRORREPORT:PROMPT /NOLOGO /TLBID:1
LINK_LIBS          = "nharu.lib" "libcrypto.lib" "libidn.lib" "crypt32.lib" "ws2_32.lib" "kernel32.lib" "user32.lib" "advapi32.lib" 
					
LIB_PATH           = /LIBPATH:"$(OUT_FILES)" /LIBPATH:"$(LIBIDN)\lib" /LIBPATH:"$(OPENSSL)\lib"

LIB_SRCS           = $(LIB_FILES)\cms_env.c $(LIB_FILES)\cms_sd.c $(LIB_FILES)\crypto.c $(LIB_FILES)\libgfshare.c \
					$(LIB_FILES)\parser.c $(LIB_FILES)\pkibr.c $(LIB_FILES)\pkix.c $(LIB_FILES)\sysservc.c $(LIB_FILES)\x509.c
LIB_HEADERS        = $(PKCS_FILES)\cryptoki.h $(PKCS_FILES)\pkcs11.h $(PKCS_FILES)\pkcs11f.h $(PKCS_FILES)\pkcs11t.h \
					$(LIB_FILES)\config.h $(LIB_FILES)\libgfshare.h $(LIB_FILES)\libgfshare_tables.h
LIB_INCLUDES       = /I"$(PROJECT_HOME)" /I"$(PROJECT_HOME)\include" /I"$(OPENSSL)\include" /I"$(LIBIDN)\include"
LIB_CVARS          = $(TARGET_CVARS) $(COMMON_CVARS) /D "_LIB"
LIB_CFLAGS         = $(TARGET_CFLAGS) $(TARGET_LIB_CFLAGS) $(COMMON_CFLAGS) /wd"4703"
LIB_LFLAGS         = $(TARGET_LIB_LFLAGS) /NOLOGO /OUT:"$(OUT_FILES)\nharu.lib"

TEST_SRCS          = $(TEST_FILES)\cadest.c $(TEST_FILES)\cert_t.c $(TEST_FILES)\cms_t.c \
					$(TEST_FILES)\crl_t.c $(TEST_FILES)\crypto_t.c $(TEST_FILES)\nmain.c $(TEST_FILES)\parser_t.c
TEST_HEADERS       = $(LIB_HEADERS) $(TEST_FILES)\test.h
TEST_INCLUDES      = $(LIB_INCLUDES) /I"$(TEST_FILES)"
TEST_CVARS         = $(TARGET_CVARS) $(COMMON_CVARS) /D "_CONSOLE"
TEST_CFLAGS        = $(TARGET_CFLAGS) $(TARGET_TEST_CFLAGS) $(COMMON_CFLAGS)
TEST_LFLAGS        = $(TARGET_LFLAGS) $(TARGET_TEST_LFLAGS) $(COMMON_LFLAGS) /SUBSYSTEM:CONSOLE /OUT:"$(OUT_FILES)\rtest.exe"

JCA_SRCS           = $(JCA_FILES)\8x256_tables.c $(JCA_FILES)\cdecode.c $(JCA_FILES)\cencode.c $(JCA_FILES)\cms_glue.c \
					$(JCA_FILES)\crc.c $(JCA_FILES)\crypto_glue.c $(JCA_FILES)\general.c $(JCA_FILES)\version.c \
					$(JCA_FILES)\versionjca.c $(JCA_FILES)\x509_glue.c
JCA_HEADERS        = $(JCA_FILES)\jca.h $(JCA_FILES)\jcms.h $(JCA_FILES)\jcrypto.h $(JCA_FILES)\version.h $(JCA_FILES)\x509.h
JCA_INCLUDES       = $(LIB_INCLUDES) /I"$(JCA_FILES)" /I"$(JAVA_HOME)\include" /I"$(JAVA_HOME)\include\win32"
JCA_CVARS          = $(TARGET_CVARS) $(COMMON_CVARS) /D "NHARUJCA_EXPORTS" /D "_WINDOWS" /D "_USRDLL" /D "_WINDLL"
JCA_CFLAGS         = $(TARGET_CFLAGS) $(TARGET_JCA_CFLAGS) $(COMMON_CFLAGS)
JCA_LFLAGS         = $(TARGET_LFLAGS) $(TARGET_JCA_LFLAGS) $(COMMON_LFLAGS) /DLL /SUBSYSTEM:WINDOWS /IMPLIB:"$(OUT_FILES)\nharujca.lib" /OUT:"$(OUT_FILES)\nharujca.dll"


ALL: $(OUT_FILES)\nharu.lib $(OUT_FILES)\rtest.exe
ALL: MKVER $(OUT_FILES)\nharujca.dll


$(OUT_FILES)\nharu.lib: $(LIB_SRCS:.c=.obj)
	$(IMPLIB) $(LIB_LFLAGS) @<<
$(OBJ_FILES)\cms_env.obj
$(OBJ_FILES)\cms_sd.obj
$(OBJ_FILES)\crypto.obj
$(OBJ_FILES)\libgfshare.obj
$(OBJ_FILES)\parser.obj
$(OBJ_FILES)\pkibr.obj
$(OBJ_FILES)\pkix.obj
$(OBJ_FILES)\sysservc.obj
$(OBJ_FILES)\x509.obj
<<

$(OUT_FILES)\rtest.exe: $(TEST_SRCS:.c=.obj)
	$(LINK) $(LINK_LIBS) $(LIB_PATH) $(TEST_LFLAGS) @<<
$(OBJ_FILES)\cadest.obj
$(OBJ_FILES)\cert_t.obj
$(OBJ_FILES)\cms_t.obj
$(OBJ_FILES)\crl_t.obj
$(OBJ_FILES)\crypto_t.obj
$(OBJ_FILES)\nmain.obj
$(OBJ_FILES)\parser_t.obj
<<

$(OUT_FILES)\nharujca.dll: $(JCA_SRCS:.c=.obj)
	$(LINK) $(LINK_LIBS) $(LIB_PATH) $(JCA_LFLAGS) @<<
$(OBJ_FILES)\8x256_tables.obj
$(OBJ_FILES)\cdecode.obj
$(OBJ_FILES)\cencode.obj
$(OBJ_FILES)\cms_glue.obj
$(OBJ_FILES)\crc.obj
$(OBJ_FILES)\crypto_glue.obj
$(OBJ_FILES)\general.obj
$(OBJ_FILES)\version.obj
$(OBJ_FILES)\versionjca.obj
$(OBJ_FILES)\x509_glue.obj
<<


$(LIB_SRCS:.c=.obj): $(LIB_SRCS) $(LIB_HEADERS)
	$(CC) $(LIB_CVARS) $(LIB_INCLUDES) $(LIB_CFLAGS) /Fo$(OBJ_FILES)\ %s

$(TEST_SRCS:.c=.obj): $(TEST_SRCS) $(TEST_HEADERS)
	$(CC) $(TEST_CVARS) $(TEST_INCLUDES) $(TEST_CFLAGS) /Fo$(OBJ_FILES)\ %s

$(JCA_SRCS:.c=.obj): $(JCA_SRCS) $(JCA_HEADERS)
	$(CC) $(JCA_CVARS) $(JCA_INCLUDES) $(JCA_CFLAGS) /Fo$(OBJ_FILES)\ %s


MKVER:
	-CALL "$(PROJECT_HOME)\jca\make_version.bat" "$(VERSION)" "$(JCA_FILES)"


CLEAN:
	-DEL /Q $(OUT_FILES)\*.*
	-DEL /Q $(OBJ_FILES)\*.*
	-DEL $(JCA_FILES)\version.c


TEST:
	-$(OUT_FILES)\rtest.exe
