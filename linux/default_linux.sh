#TODO: melhorar a definição de variáveis... assumir do ambiente mais coisas.

export BUILD_DEST=$HOME/development/build
export LOCAL_TARGET=linux
export TARGET=linux
export ANDROID_API=21
export ANDROID_NDK_ROOT=$HOME/apps/android-sdk/ndk-bundle
export BUILD_TYPE=release

export JAVA_HOME=$HOME/apps/jdk7
# Could be linked to something like /usr/lib/jvm/java-7-oracle/

export ANT_HOME=$HOME/apps/ant/
export ANT_CONTRIB=$HOME/apps/ant-contrib/
export NHARU_HOME="${NHARU_HOME:=$HOME/development/nharu/}"


export GNULIB_TOOL="${GNULIB_TOOL:=$HOME/development/3rdParty/gnulib/gnulib-tool}"
export OPENSSL_HOME="${OPENSSL_HOME:=$HOME/development/3rdParty/libssl/}"
export IDN_HOME="${IDN_HOME:=$HOME/development/3rdParty/libidn/}"
export LIB_ICONV="${LIB_ICONV:=$HOME/development/3rdParty/libiconv/}"

export VERSION=1.1.7

clean()
{
	export CC=
	export LD=
	export CPP=
	export CXX=
	export AR=
	export AS=
	export NM=
	export STRIP=
	export CXXCPP=
	export RANLIB=
	export ANDROID_PLATFORM=
	export ANDROID_ARCH=
	export HOST=
	export TARGET_PLATFORM=
	export BUILD_TARGET=
	export LIBRARY=
	export LDFLAGS=
	export CFLAGS=
	export CXXFLAGS=
	export SYS_LIBRARY=
}

ensure_dpkg()
{
	while [ -n "$1" ];
	do
		lib=$1
		inst=$(dpkg -l $lib 2>&1 | grep $lib | awk '{ print $1 }')
		if [ ! "$inst" = "ii" ]; then
			sudo apt install $lib
		fi
		shift
	done
}

ensure_yum()
{
	while [ -n "$1" ];
	do
		lib=$1
		inst=$(yum list installed $lib 2>&1 | grep $lib | awk '{ print $1 }')
		if [ -n "$inst" ]; then
			yum install $lib
		fi
		shift
	done
}


ensure()
{
	if [ -z "$(which yum)" ]; then 
		ensure_dpkg $*
	else
		ensure_yum $*
	fi

}

dwiconv()
{

	dwiconvcurdir=$PWD
	cd $(dirname $LIB_ICONV)

	if [ ! -d gnulib ]; then
		git clone https://git.savannah.gnu.org/git/gnulib.git
	fi
	git clone https://git.savannah.gnu.org/git/libiconv.git $LIB_ICONV
	cd $LIB_ICONV
	git checkout v1.15 -b nharu_build

	ensure gperf
	ensure autoconf
	ensure automake
	ensure groff

	if [ ! -d "$HOME/bin" ]; then
		mkdir $HOME/bin
	fi

	if [ ! -f ~/bin/autoheader-2.69 ]; then
		ln -s /usr/bin/autoheader ~/bin/autoheader-2.69
	fi

	if [ ! -f ~/bin/autoconf-2.69 ]; then
		ln -s /usr/bin/autoconf ~/bin/autoconf-2.69
	fi

	./autogen.sh
	cd $dwiconvcurdir
}


mkiconv()
{
	mkiconvcurdir=$PWD
	if [ ! -d "$LIB_ICONV" ]; then
	   dwiconv
	fi

	cd $LIB_ICONV
	if [ ! -f configure ]; then
		./autogen.sh
	fi

	if [ -f Makefile ]; then
		make clean
		make distclean
	fi

	if [ "$TARGET" = "linux" ]; then
		./configure --with-pic --disable-shared --prefix=$1/iconv/$3  --target=$3
	else
		echo source $TITI_DIR/droid-libs.sh --target=iconv --prefix=$1 --ndk=$4 --api-level=$5 --arch=$3
		source $TITI_DIR/droid-libs.sh --target=iconv --prefix=$1 --ndk=$4 --api-level=$5 --arch=$3
		./configure --with-pic --disable-shared --prefix=$BUILD_TARGET/$LIBRARY/$ANDROID_PLATFORM/$ANDROID_ABI \
				     --host=$HOST-android-linux --target=$TARGET_PLATFORM  
	fi
	make 
	make install
	cd $mkiconvcurdir
}


dwidn()
{
	dwidncurdir=$PWD
	cd $(dirname $IDN_HOME)
	git clone https://git.savannah.gnu.org/git/libidn.git $IDN_HOME
	cd $IDN_HOME
	git checkout libidn-1-32 -b nharu_build
	make bootstrap
	cd $mkidncurdir
}

mkidn()
{
	mkidncurdir=$PWD
	if [ ! -d "$IDN_HOME" ]; then
	   dwidn
	fi
	cd $IDN_HOME

	if [ -f Makefile ]; then
		make clean
		make distclean
	fi

	if [ "$TARGET" = "linux" ]; then
		echo -n "#include <stdint.h>" > lib/idn-int.h
		./configure --disable-silent-rules --enable-threads=posix --disable-shared --with-pic --with-libiconv-prefix=$1/iconv/$3 --prefix=$1/idn/$3
	else
		echo -e "#include <limits.h>\n#include <stdint.h>" > lib/idn-int.h
		source $TITI_DIR/droid-libs.sh --target=idn --prefix=$1 --ndk=$4 --api-level=$5 --arch=$3
		 gl_cv_header_working_stdint_h=yes ./configure --disable-silent-rules \
		    --disable-shared --with-pic \
		    --with-libiconv-prefix=$BUILD_TARGET/iconv/$ANDROID_PLATFORM/$ANDROID_ABI \
		    --prefix=$BUILD_TARGET/$LIBRARY/$ANDROID_PLATFORM/$ANDROID_ABI \
		    --host=$HOST-android-linux --target=$TARGET_PLATFORM \
		    
	fi
	make 
	make install
	cd $mkidncurdir
}


dwopenssl()
{
	dwopensslcurdir=$PWD
	cd $(dirname $OPENSSL_HOME)
	git clone https://github.com/openssl/openssl $OPENSSL_HOME
	cd $OPENSSL_HOME
#	git checkout OpenSSL_1_0_2g
	git checkout OpenSSL_1_1_0f -b nharu_build
	cd $dwopensslcurdir
}


mkopenssl()
{

	clean

	mkopensslcurdir=$PWD

	if [ ! -d "$OPENSSL_HOME" ]; then
	   dwopenssl
	fi

	cd $OPENSSL_HOME


	if [ ! -f include/openssl/des_old.h  ]; then
		echo $PWD
		echo "# include <openssl/des.h>" > include/openssl/des_old.h
	fi
	

	if [ "$TARGET" = "linux" ]; then
		# The env must be clean or else...
		./config threads no-shared -fPIC --prefix=$1/ssl/$3 --openssldir=$1/ssl/$3
	else
		source $TITI_DIR/droid-ssl.sh --prefix=$1/ssl --ndk=$4 --api-level=$5 --arch=$3 --with-openssl=$OPENSSL_HOME

		echo "******************************************************"

		if [  "$TARGET" = "x86_64" ]; then
			./Configure $SYSTEM  threads no-shared -fPIC no-ssl2 no-ssl3 no-comp no-hw no-engine \
			--openssldir=$BUILD_TARGET/$ANDROID_PLATFORM/$ANDROID_ABI --prefix=$BUILD_TARGET/$ANDROID_PLATFORM/$ANDROID_ABI
		else
			./config  threads no-shared -fPIC no-ssl2 no-ssl3 no-comp no-hw no-engine \
			--openssldir=$BUILD_TARGET/$ANDROID_PLATFORM/$ANDROID_ABI --prefix=$BUILD_TARGET/$ANDROID_PLATFORM/$ANDROID_ABI
		fi
	fi
	make clean
	make -n depend
	make all
	if [ "$TARGET" = "linux" ]; then
		make install
	else
		make install  CC=$ANDROID_GCC RANLIB=$ANDROID_RANLIB
	fi
	cd $mkopensslcurdir;
}

mknharu()
{
	mknharucurdir=$PWD
	cd $NHARU_HOME

	clean
	if [ "$TARGET" = "linux" ]; then
		$NHARU_HOME/linux/config.sh --prefix=$1  \
			--with-openssl=$1/ssl/$3 --with-idn=$1/idn/$3  \
			--with-iconv=$1/iconv/$3 --enable-shared --enable-pthread \
			--enable-java  --with-jdk=$JAVA_HOME --with-ant=$ANT_HOME \
			--with-ant-contrib=$ANT_CONTRIB --target=$3 --static-gclib 
	else
		source $TITI_DIR/droid-libs.sh --target=iconv --prefix=$1 --ndk=$4 --api-level=$5 --arch=$3

		$NHARU_HOME/linux/config.sh --target=$ANDROID_PLATFORM/$ANDROID_ABI --disable-java \
			--with-openssl=$1/ssl/$ANDROID_PLATFORM/$ANDROID_ABI \
			--with-idn=$1/idn/$ANDROID_PLATFORM/$ANDROID_ABI \
			--with-iconv=$1/iconv/$ANDROID_PLATFORM/$ANDROID_ABI \
			--prefix=$1 --syslib=$SYS_LIBRARY --disable-shared
	fi

	if [ "$6" == "debug" ]; then
		export TYPE="_DEBUG_=1"
	else
		if [ "$6" == "fips" ]; then
			export TYPE="_FIPS_=1"
		fi
	fi

	make -C src clean $TYPE
	make -C src $TYPE

	if [ "$TARGET" = "linux" ]; then
		cd jca
		make -C ./native clean $TYPE
		$ANT_HOME/bin/ant -DANT_CONTRIB_LIB=$ANT_CONTRIB/ant-contrib.jar -DVERSION=$VERSION
		make -C ./native $TYPE
		$ANT_HOME/bin/ant -DANT_CONTRIB_LIB=$ANT_CONTRIB/ant-contrib.jar -DBUILD_DEST=$1/nharu/$3/lib/ install
		make -C ./native install $TYPE
		cd ..
		make -C test clean 
		make -C test
	fi
	make -C src install $TYPE
	cd $mknharucurdir
}




all()
{
	mkiconv "$@"
	mkidn "$@"
	mkopenssl "$@"
	mknharu "$@"	
	beep
}



if [ -n "$2" ]; then
	export TARGET=$2
fi

if [ -n "$3" ]; then
	export BUILD_TYPE=$3
fi

if [ -n "$4" ]; then
	export ANDROID_API=$4
else
	if [ "$TARGET" = "x86_64" ]; then
		export ANDROID_API=21
		# minimum api for 64. Default if no explicit setting used.
	fi
fi


usage()
{

	echo -e "\n usage: default_linux.sh <libopt> [<target> <debug|release(default)> <android-api(default:21)> ]"
	echo -e "\n available libopt options:"
	echo -e "\ticonv  - Configure and build libiconv, clone if necessary."
	echo -e "\tidn    - Configure and build libidn, clone if necessary."
	echo -e "\tssl    - Configure and build openssl, clone if necessary."
	echo -e "\tnharu  - Configure and build nharu."
	echo -e "\tall    - Does everything."
	echo -e "\n available target options:"
	echo -e "\tlinux  - Settings for current linux.(default)"
	echo -e "\tarm    - Settings for android arm."
	echo -e "\tx86    - Settings for android x86."
	echo -e "\tx86_64 - Settings for android x86_64(not working yet?)."


}


set -e

case $1 in

	(iconv) mkiconv $BUILD_DEST $LOCAL_TARGET $TARGET $ANDROID_NDK_ROOT $ANDROID_API $BUILD_TYPE
	;;
	(idn) mkidn $BUILD_DEST $LOCAL_TARGET $TARGET $ANDROID_NDK_ROOT $ANDROID_API $BUILD_TYPE
	;;
      (ssl) mkopenssl $BUILD_DEST $LOCAL_TARGET $TARGET $ANDROID_NDK_ROOT $ANDROID_API $BUILD_TYPE
	;;
      (nharu) mknharu $BUILD_DEST $LOCAL_TARGET $TARGET $ANDROID_NDK_ROOT $ANDROID_API $BUILD_TYPE
	;;
      (all) all $BUILD_DEST $LOCAL_TARGET $TARGET $ANDROID_NDK_ROOT $ANDROID_API $BUILD_TYPE
	;;
      (*) usage
	;;
esac


