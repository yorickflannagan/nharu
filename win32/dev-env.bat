@ECHO OFF
:: * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
:: Nharu Library
:: Environment for Windows Development
:: -----------------------------
:: Required software
:: -----------------------------
:: MS Visual Studio Community	Required to to build native library	https://visualstudio.microsoft.com/pt-br/downloads/
:: Git SCM						Software configuration management	https://git-scm.com/
:: Dr. Memory Debugger			Required to look for memory leaks	https://drmemory.org/
:: Netwide Assembler			Required to compile OpenSSL			https://www.nasm.us/
:: Active Perl					Required to compile OpenSSL 		http://www.activestate.com/activeperl
:: Java Development Kit 32 bits	Required to build					http://www.oracle.com/technetwork/java/javase/downloads/
:: Java SDK 7 32 bits			Required by build           		https://www.oracle.com/technetwork/java/javase/downloads/java-archive-downloads-javase7-521261.html
:: Apache Ant					Required to build JCA				https://ant.apache.org/
:: Ant Contrib Tasks			Required to build JCA				http://ant-contrib.sourceforge.net/
:: Open SSL						Nharu dependency					https://github.com/openssl/openssl
:: GNU Libidn					Nharu dependency					https://git.savannah.gnu.org/git/libidn.git
:: -----------------------------
:: Copyleft (C) 2015 by The Crypthing Initiative
:: Authors:
::   diego.sohsten@caixa.gov.br
:: 	 yorick.flannagan@gmail.com
:: * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *

ECHO.
ECHO  * * * * * * * * * * * * * * * * * * * * * * * *
ECHO  Nharu Library
ECHO  Environment for Windows Development
ECHO  -----------------------------------------------
ECHO  Copyleft (C) 2015 by The Crypthing Initiative
ECHO  Authors:
ECHO    diego.sohsten@caixa.gov.br
ECHO  	yorick.flannagan@gmail.com
ECHO.
ECHO  * * * * * * * * * * * * * * * * * * * * * * * *
ECHO.

:: Required paths
FOR %%i IN ("%~dp0..") DO SET "_HOME=%%~fi"
CALL:GET_PREFIX %_HOME%
SET _PREFIX=%_PREFIX%3rdparty\nharu
SET _VERSION=1.1.10
SET _OPENSSL=C:\Users\developer\dev\3rdparty\openssl\
SET _LIBIDN=C:\Users\developer\dev\3rdparty\idn\
SET _JAVA_HOME=C:\Users\developer\java\
SET _ANT_HOME=C:\Users\developer\dev\3rdparty\apache-ant-1.9.9\
SET _ANT_CONTRIB=C:\Users\developer\dev\3rdparty\ant-contrib\ant-contrib-1.0b3.jar
SET _JRE_7RT=C:\Users\developer\jdk7\jre\lib\rt.jar
SET _VS_INSTALL_PATH=C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\


:: Check arguments
FOR %%a IN (%*) DO (
    CALL:GET_ARGS "--","%%a" 
)
VERIFY >NUL
IF DEFINED --version (
	SET _VERSION=%--version%
)
IF DEFINED --prefix (
	SET _PREFIX=%--prefix%
)

:: MS NMAKE environment
CALL "%_VS_INSTALL_PATH%VC\Auxiliary\Build\vcvarsamd64_x86.bat"

:: Nharu environment
SET OPENSSL=%_OPENSSL:~0,-1%
SET LIBIDN=%_LIBIDN:~0,-1%
SET HOME=%_HOME%
SET JAVA_HOME=%_JAVA_HOME:~0,-1%
SET ANT_HOME=%_ANT_HOME:~0,-1%
SET ANT_CONTRIB=%_ANT_CONTRIB%
SET JRE_7=%_JRE_7RT%
SET VERSION=%_VERSION%
SET PREFIX=%_PREFIX%
GOTO:END

:GET_PREFIX
FOR %%i IN ("%~dp1") DO SET "_PREFIX=%%~fi"
GOTO:EOF

:GET_ARGS
:: PROCESS COMAND LINE ARGUMENT OF TYPE --arg=value
:: %~1: ARGUMENT MARKER (USUALY --)
:: %~2: OUT
ECHO.%~2 | FINDSTR /C:"%~1" 1>nul
IF NOT ERRORLEVEL 1 (
	SET __KEY=%~2
) ELSE (
	SET __VALUE=%~2
)
IF DEFINED __KEY (
	SET %__KEY%=%~2
)
IF DEFINED __VALUE (
	IF DEFINED __KEY (
		SET %__KEY%=%~2
	)
	SET __KEY=
	SET __VALUE=
)
GOTO:EOF

:: Clean-up
:END
SET _HOME=
SET _OPENSSL=
SET _LIBIDN=
SET _JAVA_HOME=
SET _ANT_HOME=
SET _ANT_CONTRIB=
SET _JRE_7RT=
SET _VS_INSTALL_PATH=
SET _VERSION=
SET _PREFIX=
SET __KEY=
SET __VALUE=
