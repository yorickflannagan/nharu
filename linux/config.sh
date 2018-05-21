#!/bin/bash

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Nharu Libraries build facility
# Copyleft (c) 2015 by The Crypthing Initiative
#
# Warnings:
# For debuggin installation, set CFLAGS environment variable with at least -D_DEBUG_
# For struct alignment, set CFLAGS environment variable with at least -D_ALIGN_
#
# Variables exported to make files:
#	BUILD_TARGET: Installation directory
#	OPENSSL_INCLUDE: OpenSSL headers
#	OPENSSL_LIB: OpenSSL libraries (required if --enable-shared)
#	IDN_INCLUDE: GNU IDN headers
#	IDN_LIB: GNU IDN library (required if --enable-shared)
#       ICONV_LIB: GNU Iconv library (if required)
#	JAVA_INCLUDE: JDK base include header (required if --enable-java or --enable-shared)
#	JAVA_PLATFORM: JDK system dependent include header (required if --enable-java or --enable-shared)
#	DLA_LIB: Linux libdl.a (required if --enable-shared)
#	ANT_HOME: Apache Ant root directory (required if --enable-java)
#	ANT_CONTRIB: Ant Contrib library (required if --enable-java)
#	CC: ANSI C Compiler
#	AR: Archiver
#	CFLAGS: Compiler flags
#	ARFLAGS: Archiver flags
#	LDFLAGS: Linker flags
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# TODO
#	Project Makefile
#	install target
#	@if [ -d "$(BUILD_TARGET)/include/libnharu" ]; then rm -f -R "$(BUILD_TARGET)/include/libnharu"; fi; \
#	if [ -d "$(BUILD_TARGET)/include/pkcs11" ]; then rm -f -R "$(BUILD_TARGET)/include/pkcs11"; fi;      \
#	if [ -d "$(BUILD_TARGET)/lib" ]; then rm -f -R "$(BUILD_TARGET)/lib"; fi;                            \
#	Warn: under debug must specify -D_DEBUG_
#	Warn: under fips must specify -D_FIPS_

isContained() { [ -z "${2##*$1*}" ]; }
error() { printf "%s\n" "$1"; exit 1; }
usage() {
	printf "%s\n"     "* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *"
	printf "%s\n"     "Nharu libraries installation tool"
	printf "%s\n"     "Optional arguments:"
	printf "%s\n"     "--target: target platform. Default value: linux"
	printf "%s\n"     "--prefix: libraries root install directory for each target. Default value: $HOME/development/build"
	printf "%s\n"     "--with-openssl: OpenSSL installation directoy. If not supplied, it is sought from $HOME directory"
	printf "%s\n"     "--with-idn: GNU IDN installation directoy. If not supplied, it is sought from $HOME directory"
	printf "%s\n"     "--with-iconv: GNU Iconv installation directory. If not supplied, it is presumed system wide available."
	printf "%s\n"     "--syslib: location of system libraries libdl.so and libpthread.so"
	printf "%s\n"     "--static-gclib - Enables static compilation with gclib."
	printf "%s\n"     "--enable-FEATURE or --disable-FEATURE. Available features:"
	printf "\t%s\n"   "java: if enabled, Java packages are built by Apache Ant;"
	printf "\t%s\n"   "shared: if disabled JNI shared library is not built."
	printf "\t%s\n"   "pthread: if disabled libpthread.so is not included in linkage"
	printf "%s\n"     "if --enable-java the following resources must be supplied:"
	printf "\t%s\n"   "--with-jdk: JDK installation directoy or $JAVA_HOME environment variable"
	printf "\t%s\n"   "--with-ant: Apache Ant Java compiler utility. If not supplied, it is sought from $HOME directory"
	printf "\t%s\n"   "--with-ant-contrib: Apache Ant utility. If not supplied, it is sought from $HOME directory"
	printf "%s\n"     "* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *"
}


printf "%s\n" "* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *"
printf "%s\n" "Nharu libraries install configuration"
source="${BASH_SOURCE[0]}"
while [ -h "$source" ]; do
	dir="$( cd -P "$( dirname "$source" )" && pwd )"
	source="$(readlink "$source")"
	[[ $source != /* ]] && source="$dir/$source"
done
CUR="$( cd -P "$( dirname "$source" )" && pwd )"
PARENT=$(dirname $CUR)
TARGET="linux"
BUILD_TARGET="$HOME/development/build"
ENABLE_JAVA=
ENABLE_SHARED="true"
ENABLE_PTHREAD="true"

# COMMAND LINE
parm=0
sep='='
while [ $# -ne 0 ]
do
	parm=1
	case $1 in
		(*"$sep"*)
			key=${1%%"$sep"*}
			value=${1#*"$sep"}
			;;
		(*)
			key=$1
			value=
			;;
	esac
	case $key in
		(--target) TARGET="$value"
		;;
		(--prefix) BUILD_TARGET="$value"
		;;
		(--enable-java) ENABLE_JAVA="true"
		;;
		(--disable-java) ENABLE_JAVA=
		;;
		(--enable-shared) ENABLE_SHARED="true"
		;;
		(--disable-shared) ENABLE_SHARED=
		;;
		(--enable-pthread) ENABLE_PTHREAD="true"
		;;
		(--disable-pthread) ENABLE_PTHREAD=
		;;
		(--with-openssl) OPENSSL="$value"
		;;
		(--static-gclib) STATICGCLIB="true"
		;;
		(--with-idn) IDN="$value"
		;;
		(--with-iconv) LIB_ICONV="$value"
		;;
		(--with-jdk) JDK="$value"
		;;
		(--with-ant) ANT_HOME="$value"
		;;
		(--with-ant-contrib) ANT_CONTRIB="$value"
		;;
		(--syslib) DLA_LIB="$value"
		;;
		(--help)
			usage
			exit 0
		;;
		(*)
			printf "Invalid argument %s\n" "$key"
			usage
			exit 1
		;;
	esac
	shift
done
BUILD_TARGET="$BUILD_TARGET/nharu/$TARGET"


# DEPENDENCIES
printf "%s\n" "Checking project dependencies..."
if [ -z "$OPENSSL" ]; then
	found=$(find $HOME -type d ! -perm -g+r,u+r,o+r -prune -o -name opensslconf.h -printf "%T@ %p\n" | sort -n | tail -1 | cut -f2- -d" ")
	if [ -n "$found" ]; then OPENSSL=$(dirname $(dirname $(dirname $found))); fi
fi

if [ -f "$OPENSSL/include/openssl/opensslconf.h" -a -f "$OPENSSL/lib/libcrypto.a" ]; then
	OPENSSL_INCLUDE="$OPENSSL/include"
	OPENSSL_LIB="$OPENSSL/lib"
else error "Could not find OpenSSL instalation directory"; fi
printf "OpenSSL found at directory %s\n" "$OPENSSL"

if [ -z "$IDN" ]; then
	found=$(find $HOME -type d ! -perm -g+r,u+r,o+r -prune -o -name stringprep.h -printf "%T@ %p\n" | sort -n | tail -1 | cut -f2- -d" ")
	if [ -n "$found" ]; then IDN=$(dirname $(dirname $found)); fi
fi

if [ -f "$IDN/include/stringprep.h" -a -f "$IDN/lib/libidn.a" ]; then
	IDN_INCLUDE="$IDN/include"
	IDN_LIB="$IDN/lib"
else error "Could not find GNU Libidn instalation directory"; fi
printf "GNU Libidn found at directory %s\n" "$IDN"

if [ -z "$DLA_LIB" ]; then
	DLIB=$(find /usr/lib -name libdl.* 2>/dev/null)
	if [ -z "$DLIB" ]; then
		printf "Libdl not helping broadening the search"
		DLIB=$(find /usr -name libdl.* 2>/dev/null)
	fi
	DLA_LIB=$(echo "$DLIB" | grep libdl.dylib | tail -1)
	if [ -z $DLA_LIB ]; then DLA_LIB=$(echo "$DLIB" | grep libdl.so | tail -1); fi
	DLA_LIB=$(dirname $DLA_LIB)
fi
if [ ! -f "$DLA_LIB/libdl.so"  -a  ! -f "$DLA_LIB/libdl.dylib" ]; then error "Could not find system libraries"; fi
printf "System library found at %s\n" "$DLA_LIB"

if [ -n "$LIB_ICONV" ]; then
	if [ ! -f "$LIB_ICONV/lib/libiconv.la" ]; then error "Could not find GNU Iconv installation directory"; fi
	BASE_LIBS="-lnharu -lcrypto -lidn -liconv"
	ICONV_LIB="-L$LIB_ICONV/lib"
else BASE_LIBS="-lnharu -lcrypto -lidn"; fi
if [ -n "$ENABLE_PTHREAD" ]; then SYS_LIBS="-lpthread -ldl";
else SYS_LIBS="-ldl"; fi
IMP_LIBS="$BASE_LIBS $SYS_LIBS"

# JNI DEPENDENCIES
if [ -n "$ENABLE_SHARED" -o -n "$ENABLE_JAVA" ]; then
	if [ -z "$JDK" ]; then
		if [ -n "$JAVA_HOME" ]; then JDK="$JAVA_HOME";
		else
			java=$(find $HOME -type d ! -perm -g+r,u+r,o+r -prune -o -name jni.h -printf "%T@ %p\n" | sort -n | tail -1 | cut -f2- -d" ")
			if [ -n "$java" ]; then JDK=$(dirname $(dirname ($java))); fi
		fi
	fi
	if [ -f "$JDK/include/jni.h" -a -f "$JDK/include/linux/jni_md.h" ]; then
		JAVA_INCLUDE="$JDK/include"
		JAVA_PLATFORM="$JDK/include/linux"
	else error "Could not find JDK instalation directory"; fi
	printf "JDK found at directory %s\n" "$JDK"
fi

# JAVA DEPENDENCIES
if [ -n "$ENABLE_JAVA" ]; then
	if [ -z "$ANT_HOME" ]; then
		ant=$(find $HOME -type d ! -perm -g+r,u+r,o+r -prune -o -name runant.py -printf "%T@ %p\n" | sort -n | tail -1 | cut -f2- -d" ")
		if [ -n "$ant" ]; then ANT_HOME=$(dirname $(dirname ($ant))); fi
	fi
	if [ ! -f "$ANT_HOME/bin/ant" ]; then
		printf "%s\n" "Could not find Apache Ant installation directory"
		exit 1
	fi
	printf "Apache Ant found at %s\n" "$ANT_HOME"
	if [ -z "$ANT_CONTRIB" ]; then
		ANT_CONTRIB=$(find $HOME -type d ! -perm -g+r,u+r,o+r -prune -o -name ant-contrib*.jar -printf "%T@ %p\n" | sort -n | tail -1 | cut -f2- -d" ")
		if [ ! -f "$ANT_CONTRIB" ]; then
			printf "%s\n" "Could not find Ant Contrib library"
			exit 1
		fi
	fi
	printf "Ant Contrib library found at %s\n" "$ANT_CONTRIB"
fi

# COMPILATION FLAGS
if [ -z "$CC" ]; then
	CC="gcc"
fi
if [ -z "$AR" ]; then
	AR="ar"
fi
if [ -z "$CFLAGS" ]; then
	CFLAGS="-pedantic-errors -pedantic -Wall -ansi -Winline -Wunused-parameter "
	if [ -n "$ENABLE_PTHREAD" ]; then CFLAGS="$CFLAGS -pthread"; fi
fi
if [ -z "$ARFLAGS" ]; then
	ARFLAGS="-r -s"
fi
if [ -z "$LDFLAGS" ]; then
	if [ -z "$STATICGCLIB" ]; then
		LDFLAGS="-shared-libgcc -Xlinker -z -Xlinker defs"
	else
		LDFLAGS="-static-libgcc -Xlinker -z -Xlinker defs"
	fi
fi
CC="$CC"
AR="$AR"
CFLAGS="$CFLAGS"
ARFLAGS="$ARFLAGS"
LDFLAGS="$LDFLAGS"
sys=$(uname -a | grep x86_64)
if [ -n "$sys" ]; then
	if ! isContained "-fPIC" "$LDFLAGS" ; then LDFLAGS="$LDFLAGS -fPIC"; fi
	if ! isContained "-fPIC" "$CFLAGS" ; then CFLAGS="$CFLAGS -fPIC"; fi
fi
if [ -n "$ENABLE_PTHREAD" ]; then
	if ! isContained "-pthread" "$CFLAGS" ; then CFLAGS="$CFLAGS -pthread"; fi
fi


#CLEAN-UP
printf "%s\n" "Nharu library old configuration clean-up..."
if [ -f "$PARENT/src/Makefile" ]; then make --directory="$PARENT/src" clean; fi
if [ -f "$PARENT/jca/native/Makefile" ]; then make --directory="$PARENT/jca/native" clean; fi
if [ -f "$PARENT/test/Makefile" ]; then make --directory="$PARENT/test" clean; fi


# GENERATE NHARU ARCHIVE
printf "%s\n" "Makefiles generation..."
if [ ! -f "$CUR/static.in" ]; then
	printf "Could not find file %s/static.in\n" "$CUR"
	exit 1
fi
printf "%s\n" "# # # # # # # # # # # # # # # # # # # # # # # #">"$PARENT/src/Makefile"
printf "%s\n" "# Makefile of Nharu static library">>"$PARENT/src/Makefile"
printf "%s\n" "# Copyleft (C) 2015 by The Crypthing Initiative">>"$PARENT/src/Makefile"
printf "%s\n" "# Generated by configure. Do not edit">>"$PARENT/src/Makefile"
printf "%s\n" "#">>"$PARENT/src/Makefile"
printf "%s\n" "# For debugging set CFLAGS with -D_DEBUG_">>"$PARENT/src/Makefile"
printf "%s\n" "# For structure alignment set CLFAGS with -D_ALIGN_">>"$PARENT/src/Makefile"
printf "%s\n" "# # # # # # # # # # # # # # # # # # # # # # # #">>"$PARENT/src/Makefile"
IFS=''
while read -r line || [[ -n "$line" ]]; do
	new="${line/\_CC_/$CC}"
	new="${new/\_AR_/$AR}"
	new="${new/\_BUILD_TARGET_/$BUILD_TARGET}"
	new="${new/\_CFLAGS_/$CFLAGS}"
	new="${new/\_ARFLAGS_/$ARFLAGS}"
	new="${new/\_OPENSSL_INCLUDE_/$OPENSSL_INCLUDE}"
	new="${new/\_IDN_INCLUDE_/$IDN_INCLUDE}"
	printf "%s\n" $new>>"$PARENT/src/Makefile"
done < "$CUR/static.in"
printf "%s\n" "Nharu static library Makefile generated"

# GENERATE NHARU JCA SHARED OBJECT
if [ -n "$ENABLE_SHARED" ]; then
	if [ ! -f "$CUR/shared.in" ]; then
		printf "Could not find file %s/jca.in\n" "$CUR"
		exit 1
	fi
	printf "%s\n" "# # # # # # # # # # # # # # # # # # # # # # # #">"$PARENT/jca/native/Makefile"
	printf "%s\n" "# Makefile Makefile Nharu JCA shared library">>"$PARENT/jca/native/Makefile"
	printf "%s\n" "# Copyleft (C) 2015 by The Crypthing Initiative">>"$PARENT/jca/native/Makefile"
	printf "%s\n" "# Generated by configure. Do not edit">>"$PARENT/jca/native/Makefile"
	printf "%s\n" "#">>"$PARENT/jca/native/Makefile"
	printf "%s\n" "# For debugging set CFLAGS with -D_DEBUG_">>"$PARENT/jca/native/Makefile"
	printf "%s\n" "# For structure alignment set CLFAGS with -D_ALIGN_">>"$PARENT/jca/native/Makefile"
	printf "%s\n" "# # # # # # # # # # # # # # # # # # # # # # # #">>"$PARENT/jca/native/Makefile"
	IFS=''
	while read -r line || [[ -n "$line" ]]; do
		new="${line/\_CC_/$CC}"
		new="${new/\_BUILD_TARGET_/$BUILD_TARGET}"
		new="${new/\_CFLAGS_/$CFLAGS}"
		new="${new/\_LDFLAGS_/$LDFLAGS}"
		new="${new/\_OPENSSL_INCLUDE_/$OPENSSL_INCLUDE}"
		new="${new/\_IDN_INCLUDE_/$IDN_INCLUDE}"
		new="${new/\_JAVA_INCLUDE_/$JAVA_INCLUDE}"
		new="${new/\_JAVA_PLATFORM_/$JAVA_PLATFORM}"
		new="${new/\_OPENSSL_LIB_/$OPENSSL_LIB}"
		new="${new/\_IDN_LIB_/$IDN_LIB}"
		new="${new/\_DLA_LIB_/$DLA_LIB}"
		new="${new/\_IMP_LIBS_/$IMP_LIBS}"
		new="${new/\_ICONV_LIB_/$ICONV_LIB}"
		printf "%s\n" $new>>"$PARENT/jca/native/Makefile"
	done < "$CUR/shared.in"
	printf "%s\n" "Nharu JCA shared library Makefile generated"
fi

# GENERATE NHARU BASIC TEST APP
if [ ! -f "$CUR/native-test.in" ]; then
	printf "Could not find file %s/test.in\n" "$CUR"
	exit 1
fi
printf "%s\n" "# # # # # # # # # # # # # # # # # # # # # # # # # #">"$PARENT/test/Makefile"
printf "%s\n" "# Makefile Makefile Nharu static library test app">>"$PARENT/test/Makefile"
printf "%s\n" "# Copyleft (C) 2015 by The Crypthing Initiative">>"$PARENT/test/Makefile"
printf "%s\n" "# Generated by configure. Do not edit">>"$PARENT/test/Makefile"
printf "%s\n" "#">>"$PARENT/test/Makefile"
printf "%s\n" "# For debugging set CFLAGS with -D_DEBUG_">>"$PARENT/test/Makefile"
printf "%s\n" "# For structure alignment set CLFAGS with -D_ALIGN_">>"$PARENT/test/Makefile"
printf "%s\n" "# # # # # # # # # # # # # # # # # # # # # # # # # #">>"$PARENT/test/Makefile"
IFS=''
while read -r line || [[ -n "$line" ]]; do
	new="${line/\_CC_/$CC}"
	new="${new/\_CFLAGS_/$CFLAGS}"
	new="${new/\_LDFLAGS_/$LDFLAGS}"
	new="${new/\_OPENSSL_INCLUDE_/$OPENSSL_INCLUDE}"
	new="${new/\_IDN_INCLUDE_/$IDN_INCLUDE}"
	new="${new/\_OPENSSL_LIB_/$OPENSSL_LIB}"
	new="${new/\_IDN_LIB_/$IDN_LIB}"
	new="${new/\_DLA_LIB_/$DLA_LIB}"
	new="${new/\_IMP_LIBS_/$IMP_LIBS}"
	new="${new/\_ICONV_LIB_/$ICONV_LIB}"
	printf "%s\n" $new>>"$PARENT/test/Makefile"
done < "$CUR/native-test.in"
printf "%s\n" "Nharu static library test application Makefile generated"

printf ".............\n"
printf "CC          = %s\n" "$CC"
printf "AR          = %s\n" "$AR"
if [ -n "$CXX" ]; then
printf "CXX         = %s\n" "$CXX"
fi
printf "Install     = %s\n" "$BUILD_TARGET"
if [ -n "$ENABLE_SHARED" ]; then
printf "JNI Lybrary = yes\n"
else
printf "JNI Lybrary = no\n"
fi
printf "CFLAGS      = %s\n" "$CFLAGS"
printf "ARFLAGS     = %s\n" "$ARFLAGS"
if [ -n "$CXXFLAGS" ]; then
printf "CXXFLAGS    = %s\n" "$CXXFLAGS"
fi
printf "OpenSSL     = %s\n" "$OPENSSL"
printf "GNU IDN     = %s\n" "$IDN"
if [ -n "$LIB_ICONV" ]; then
printf "GNU Iconv   = %s\n" "$LIB_ICONV"
fi
printf ".............\n"


printf "%s\n" "Nharu environment configuration complete!"
printf "%s\n" "* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *"
