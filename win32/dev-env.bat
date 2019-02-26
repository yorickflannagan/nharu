@ECHO OFF
:: * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
:: Kryptonite
:: Cryptographic extension for Internet browsers
:: Environment for Windows Development
::
:: Required software
:: -----------------------------
:: MS Visual Studio Community	Required to install Windows SDK and other utilities		https://visualstudio.microsoft.com/pt-br/downloads/
:: Netwide Assembler			Required to compile OpenSSL								https://www.nasm.us/
:: Active Perl					Required to compile OpenSSL and Nharu scripts			http://www.activestate.com/activeperl
:: GnuWin32						Required by Nharu scripts								http://gnuwin32.sourceforge.net/
:: Java Development Kit 32 bits	Required by Nharu build									http://www.oracle.com/technetwork/java/javase/downloads/
:: MS Windows CNG SDK			Required by project										https://www.microsoft.com/en-us/download/details.aspx?id=1251
:: Wix Toolset					Required by project										http://wixtoolset.org/releases/
:: Git							Required by project										ftp.cetec.df.caixa get Software/Autorizados/Git_Client/Git-2.16.1-64-bit.exe
:: MS Visual Studio Project		Required by project										https://code.visualstudio.com/download
:: Node JS and NPM				Required by project										ftp.cetec.df.caixa get Software/Autorizados/NodeJS_8.6.0/node-v8.6.0-x64.msi
::
:: Third party components
:: -----------------------------
:: Nharu Library				Required by project										https://bitbucket.org/yakoana/nharu.git
:: GNU Libidn					Required by Nharu										https://git.savannah.gnu.org/git/libidn.git
:: Open SSL						Required by Nharu										https://github.com/openssl/openssl
:: Apache Ant					Required by Nharu										https://ant.apache.org/
:: Ant Contrib Tasks			Required by Nharu										http://ant-contrib.sourceforge.net/
:: -----------------------------
:: Copyleft (C) 2018 by Caixa Econômica Federal
:: Authors:
:: 		diego.sohsten@caixa.gov.br
:: 		yorick.flannagan@gmail.com
:: * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *

SET _VSSTUDIO=%ProgramFiles(x86)%\Microsoft Visual Studio\2017\Community
SET _SDKS=%ProgramFiles(x86)%\Windows Kits
SET _NASM=%ProgramFiles(x86)%\NASM
SET _PERL=%ProgramFiles%\Perl64\bin
SET _GNUWIN=%ProgramFiles(x86)%\gnuwin32
SET _JAVA=%USERPROFILE%\java
SET _JRE=%USERPROFILE%\jre
SET _WIN_CNG=%ProgramFiles(x86)%\Microsoft CNG Development Kit
SET _DEV_HOME=%USERPROFILE%\dev
SET _3RDPARTY=%_DEV_HOME%\3rdparty

:: Nharu environment
SET NHARU_HOME=%_DEV_HOME%\nharu
SET ANT_CONTRIB_LIB=%_3RDPARTY%\ant-contrib\ant-contrib-1.0b3.jar
SET JAVA_HOME=%_JAVA%
SET BUILD_DEST=%_3RDPARTY%\nharu
SET JRE_7=%_3RDPARTY%\jdk1.7.0_55\jre\lib\rt.jar
SET OPENSSL=%_3RDPARTY%\openssl
SET LIBIDN=%_3RDPARTY%\idn
SET ANT_HOME=%_3RDPARTY%\apache-ant-1.9.9

:: WINDOWS SDK ENVIRONMENT
SET _PATH=%PATH%
CALL "%_VSSTUDIO%\VC\Auxiliary\Build\vcvarsamd64_x86.bat"
SET INCLUDE=%INCLUDE%;%_WIN_CNG%\Include
SET LIB=%LIB%;%_WIN_CNG%\Lib\X86
SET LIBPATH=%LIBPATH%;%_WIN_CNG%\Lib\X86
CALL SET PATH=%%PATH:%_PATH%=%%
SET PATH=%PATH%;%_PATH%;%ProgramFiles%\nodejs;%USERPROFILE%\AppData\Roaming\npm;%WIX%\bin;%_NASM%;%_PERL%;%_JRE%\bin;%ANT_HOME%\bin

:: Kryptonite environment
SET PROJECT_HOME=%_DEV_HOME%\kryptonite
SET NHARU=%_3RDPARTY%\nharu
SET OPENSSL=%OPENSSL%
SET LIBIDN=%LIBIDN%
SET MSVC=%_VSSTUDIO%\VC\Tools\MSVC\14.14.26428
SET NET_INCLUDE=%_SDKS%\NETFXSDK\4.6.1\include\um
SET WINSDK_INCLUDE=%_SDKS%\10\include\10.0.17134.0
SET WIN_CNG=%_WIN_CNG%
SET CRYPT_IMPL=_WIN_API
SET WIX=%ProgramFiles(x86)%\WiX Toolset v3.11

SET _VSSTUDIO=
SET _SDKS=
SET _NASM=
SET _PERL=
SET _GNUWIN=
SET _JAVA=
SET _JRE=
SET _WIN_CNG=
SET _DEV_HOME=
SET _3RDPARTY=
