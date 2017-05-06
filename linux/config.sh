#!/bin/bash

usage() {
	printf "%s\n"     "* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *"
	printf "%s\n"     "Nharu libraries installation tool"
	printf "%s\n"     "Optional arguments:"
	printf "%s\n"     "--prefix: libraries install directory. Default value:"
	printf "\t%s\n"   "[nharu]/libs, where [nharu] refers to project diretory"
	printf "%s\n"     "--openssl: OpenSSL installation directoy. If not supplied,"
	printf "\t%s\n"   "it is sought from user's home directory"
	printf "%s\n"     "--idn: GNU Libidn installation directoy. If not supplied,"
	printf "\t%s\n"   "it is sought from user's home directory"
	printf "%s\n"     "--enable-FEATURE or --disable-FEATURE. Available features:"
	printf "\t%s\n"   "java: if enabled, Java packages are built by Apache Ant;"
	printf "\t%s\n"   "shared: if disabled JNI shared library is not built."
	printf "%s\n"     "if --enable-java the following resources must be supplied:"
	printf "\t%s\n"   "--jdk: JDK installation directoy. If not supplied and a"
	printf "\t\t%s\n" "JAVA_HOME environment variable is not defined,"
	printf "\t\t%s\n" "it is sought from user's home directory"
	printf "\t%s\n"   "--ant: Apache Ant Java compiler utility. If not supplied,"
	printf "\t\t%s\n" "it is sought from user's home directory"
	printf "\t%s\n"   "--ant-contrib: Apache Ant utility. If not supplied,"
	printf "\t\t%s\n" "it is sought from user's home directory"
	printf "%s\n"     "* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *"
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
BUILD_TARGET="$PARENT/libs"
ENABLE_JAVA=
ENABLE_SHARED="true"

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
		(--openssl) OPENSSL="$value"
		;;
		(--idn) IDN="$value"
		;;
		(--jdk) JDK="$value"
		;;
		(--ant) ANT_HOME="$value"
		;;
		(--ant-contrib) ANT_CONTRIB="$value"
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

# DEPENDENCIES
printf "%s\n" "Checking project dependencies..."
if [ -z "$OPENSSL" ]; then
	found=$(find $HOME -type d ! -perm -g+r,u+r,o+r -prune -o -name opensslconf.h -printf "%T@ %p\n" | sort -n | tail -1 | cut -f2- -d" ")
	if [ -n "$found" ]; then
		OPENSSL=$(dirname $(dirname $(dirname $found)))
	fi
fi
if [ -f "$OPENSSL/include/openssl/opensslconf.h" -a -f "$OPENSSL/lib/libcrypto.a" ]; then
	OPENSSL_INCLUDE="$OPENSSL/include"
	OPENSSL_LIB="$OPENSSL/lib"
else
	printf "Could not find OpenSSL instalation directory %s\n" "$OPENSSL"
	exit 1
fi
printf "OpenSSL found at directory %s\n" "$OPENSSL"

if [ -z "$IDN" ]; then
	found=$(find $HOME -type d ! -perm -g+r,u+r,o+r -prune -o -name stringprep.h -printf "%T@ %p\n" | sort -n | tail -1 | cut -f2- -d" ")
	if [ -n "$found" ]; then
		IDN=$(dirname $(dirname $found))
	fi
fi
if [ -f "$IDN/include/stringprep.h" -a -f "$IDN/lib/libidn.a" ]; then
	IDN_INCLUDE="$IDN/include"
	IDN_LIB="$IDN/lib"
else
	printf "Could not find GNU Libidn instalation directory %s\n" "$IDN"
	exit 1
fi
printf "GNU Libidn found at directory %s\n" "$IDN"

# JNI DEPENDENCIES
if [ -n "$ENABLE_SHARED" -o -n "$ENABLE_JAVA" ]; then
	if [ -z "$JDK" ]; then
		if [ -n "$JAVA_HOME" ]; then
			JDK="$JAVA_HOME"
		else
			java=$(find $HOME -type d ! -perm -g+r,u+r,o+r -prune -o -name jni.h -printf "%T@ %p\n" | sort -n | tail -1 | cut -f2- -d" ")
			if [ -n "$java" ]; then
				JDK=$(dirname $(dirname ($java)))
			fi
		fi
	fi
	if [ -f "$JDK/include/jni.h" -a -f "$JDK/include/linux/jni_md.h" ]; then
		JAVA_INCLUDE="$JDK/include"
		JAVA_PLATFORM="$JDK/include/linux"
	else
		printf "%s\n" "Could not find JDK instalation directory"
		exit 1
	fi
	printf "JDK found at directory %s\n" "$JDK"
fi
if [ -n "$ENABLE_SHARED" ]; then
	DLA_LIB=$(dpkg -L libc6-dev | grep libdl\\.a | dirname  $(grep -v xen))
	if [ ! -d "$DLA_LIB" ]; then
		printf "%s\n" "Could not find libdl.a"
		exit 1
	fi
	printf "libdl.a found at %s\n" "$DLA_LIB"
fi

# JAVA DEPENDENCIES
if [ -n "$ENABLE_JAVA" ]; then
# TODO
	if [ -z "$ANT_HOME" ]; then
printf ""
	fi
fi


# COMPILATION FLAGS
if [ -z "$CC" ]; then
	CC="gcc"
fi
if [ -z "$AR" ]; then
	AR="ar"
fi
if [ -z "$CXX" ]; then
	CXX="gcc"
fi
if [ -z "$CFLAGS" ]; then
	CFLAGS="-pedantic-errors -pedantic -Wall -ansi -pthread -Winline -Wunused-parameter"
fi
if [ -z "$ARFLAGS" ]; then
	ARFLAGS="-r -s"
fi
if [ -z "$CXXFLAGS" ]; then
	CXXFLAGS="-shared -shared-libgcc -Xlinker -z -Xlinker defs"
fi
CC="$CC"
AR="$AR"
CXX="$CXX"
CFLAGS="$CFLAGS"
ARFLAGS="$ARFLAGS"
CXXFLAGS="$CXXFLAGS"
sys=$(uname -a | grep x86_64)
if [ -n "$sys" ]; then
	CFLAGS="$CFLAGS -fPIC"
	CXXFLAGS="$CXXFLAGS -fPIC"
fi


#CLEAN-UP
printf "%s\n" "Nharu library old configuration clean-up..."
if [ -f "$PARENT/src/Makefile" ]; then
	make --directory="$PARENT/src" clean
	rm -f "$PARENT/src/Makefile"
fi
if [ -f "$PARENT/jca/native/Makefile" ]; then
	make --directory="$PARENT/jca/native" clean
	rm -f "$PARENT/jca/native/Makefile"
fi
if [ -f "$PARENT/test/Makefile" ]; then
	make --directory="$PARENT/test" clean
	rm -f "$PARENT/test/Makefile"
fi
if [ -f "$PARENT/Makefile" ]; then
	rm -f "$PARENT/Makefile"
fi


printf "%s\n" "Makefiles generation..."
# OUTPUT DIRECTORY CREATION
mkdir -p "$BUILD_TARGET"
if [ $? -ne 0 ]; then
	printf "Could not create output %s directory\n" "$BUILD_TARGET"
	exit $?
fi

# GENERATE NHARU ARCHIVE
if [ ! -f "$CUR/static.in" ]; then
	printf "Could not find file %s/static.in\n" "$CUR"
	exit 1
fi
printf "%s\n" "# # # # # # # # # # # # # # # # # # # # # # # #">"$PARENT/src/Makefile"
printf "%s\n" "# Makefile of Nharu static library">>"$PARENT/src/Makefile"
printf "%s\n" "# Copyleft (C) 2015 by The Crypthing Initiative">>"$PARENT/src/Makefile"
printf "%s\n" "# Generated by configure. Do not edit">>"$PARENT/src/Makefile"
printf "%s\n" "#">>"$PARENT/src/Makefile"
printf "%s\n" "# Make optional parameters:">>"$PARENT/src/Makefile"
printf "%s\n" "#	DEBUG=1">>"$PARENT/src/Makefile"
printf "%s\n" "#	ALIGN=1">>"$PARENT/src/Makefile"
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
	printf "%s\n" "# Make optional parameters:">>"$PARENT/jca/native/Makefile"
	printf "%s\n" "#	DEBUG=1">>"$PARENT/jca/native/Makefile"
	printf "%s\n" "#	ALIGN=1">>"$PARENT/jca/native/Makefile"
	printf "%s\n" "# # # # # # # # # # # # # # # # # # # # # # # #">>"$PARENT/jca/native/Makefile"
	IFS=''
	while read -r line || [[ -n "$line" ]]; do
		new="${line/\_CC_/$CC}"
		new="${new/\_CXX_/$CXX}"
		new="${new/\_BUILD_TARGET_/$BUILD_TARGET}"
		new="${new/\_CFLAGS_/$CFLAGS}"
		new="${new/\_CXXFLAGS_/$CXXFLAGS}"
		new="${new/\_OPENSSL_INCLUDE_/$OPENSSL_INCLUDE}"
		new="${new/\_IDN_INCLUDE_/$IDN_INCLUDE}"
		new="${new/\_JAVA_INCLUDE_/$JAVA_INCLUDE}"
		new="${new/\_JAVA_PLATFORM_/$JAVA_PLATFORM}"
		new="${new/\_OPENSSL_LIB_/$OPENSSL_LIB}"
		new="${new/\_IDN_LIB_/$IDN_LIB}"
		new="${new/\_DLA_LIB_/$DLA_LIB}"
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
printf "%s\n" "# Make optional parameters:">>"$PARENT/test/Makefile"
printf "%s\n" "#	DEBUG=1">>"$PARENT/test/Makefile"
printf "%s\n" "# # # # # # # # # # # # # # # # # # # # # # # # # #">>"$PARENT/test/Makefile"
IFS=''
while read -r line || [[ -n "$line" ]]; do
	new="${line/\_CC_/$CC}"
	new="${new/\_CXX_/$CXX}"
	new="${new/\_CFLAGS_/$CFLAGS}"
	new="${new/\_OPENSSL_INCLUDE_/$OPENSSL_INCLUDE}"
	new="${new/\_IDN_INCLUDE_/$IDN_INCLUDE}"
	new="${new/\_OPENSSL_LIB_/$OPENSSL_LIB}"
	new="${new/\_IDN_LIB_/$IDN_LIB}"
	new="${new/\_DLA_LIB_/$DLA_LIB}"
	printf "%s\n" $new>>"$PARENT/test/Makefile"
done < "$CUR/native-test.in"
printf "%s\n" "Nharu JCA static library test application Makefile generated"


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
printf "OpenSSL     = %s\n" "$OPENSSL_INCLUDE"
printf "GNU IDN     = %s\n" "$IDN_INCLUDE"


printf "%s\n" "Nharu environment configuration complete!"
printf "%s\n" "* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *"


