@ECHO OFF
SETLOCAL EnableExtensions
SETLOCAL EnableDelayedExpansion

:: ERRORLEVEL CODES
:: 1 = INVALID ARGUMENT
:: 2 = INSATISFIED DEPENDENCY
:: 3 = INCORRECT ENVIRONMENT
:: 4 = MAKEFILE GENERATION FAILURE

ECHO.
ECHO * * * * * * * * * * * * * * * * * * * * *
ECHO * Nharu static libraries configuration  *
ECHO * * * * * * * * * * * * * * * * * * * * *

:STARTUP
SET ME=%~n0
SET CUR=%~dp0
FOR /F %%i IN ('dirname %CUR%') DO SET PARENT=%%i
FOR /F %%i IN ('dirname %PARENT%') DO SET ROOT=%%i
SET _PREFIX_=%ROOT%\3rdparty\nharu
SET _CVARS_=/D "WIN32" /D "NDEBUG" /D "_UNICODE" /D "UNICODE"
SET _CFLAGS_=/GS /sdl- /GL /Gm- /Gy /Gd /fp:precise /permissive- /Zc:wchar_t /Zc:inline /Zc:forScope /MD /W4 /WX- /O2 /Oy-
SET _LFLAGS_=/LTCG
SET _JCAFLAGS_=/MANIFEST:NO /LTCG /NXCOMPAT /DYNAMICBASE /MACHINE:X86 /SAFESEH /INCREMENTAL:NO /OPT:ICF /OPT:REF
FOR %%a IN (%*) DO (
    CALL:GET_ARGS "--","%%a" 
)
VERIFY >NUL
IF DEFINED --help (
	GOTO USAGE
)
IF DEFINED --prefix (
	SET _PREFIX_=%--prefix%
)
IF DEFINED --cvars (
	SET _CVARS_=%--cvars%
)
IF DEFINED --cflags (
	SET _CFLAGS_=%--cflags%
)
IF DEFINED --lflags (
	SET _LFLAGS_=%--lflags%
)
IF DEFINED --jcaflags (
	SET _JCAFLAGS_=%--jcaflags%
)
IF DEFINED --openssl (
	IF NOT EXIST %--openssl%\include\openssl\opensslconf.h (
		ECHO %ME%: --openssl argument does not point to OpenSSL install directory
		EXIT /B 1
	)
	SET OPENSSL=%--openssl%
)
IF DEFINED --libidn (
	IF NOT EXIST %--libidn%\include\stringprep.h (
		ECHO %ME%: --libidn argument does not point to GNU IDN Library install directory
		EXIT /B 1
	)
	SET LIBIDN=%--libidn%
)
IF DEFINED --java (
	IF NOT EXIST %--java%\include\win32\jni.h (
		ECHO %ME%: --java argument does not point to JDK install directory
		EXIT /B 1
	)
	SET JAVA_HOME=%--java%
)
IF DEFINED --jre (
	IF NOT EXIST %--jre%\rt.jar (
		ECHO %ME%: --jre argument does not point to JRE directory
		EXIT /B 1
	)
	SET _JRE_7_=%--jre%
)
IF DEFINED --ant (
	IF NOT EXIST %--ant%\bin\ant.bat (
		ECHO %ME%: --ant argument does not point to Apache Ant install directory
		EXIT /B 1
	)
	SET ANT_HOME=%--ant%
)
IF DEFINED --ant-contrib (
	IF NOT EXIST "%--ant-contrib%" (
		ECHO %ME%: --ant-contrib argument does not point to the library
		EXIT /B 1
	)
	SET ANT_CONTRIB=%--ant-contrib%
)
SET _PREFIX_=%_PREFIX_:\=\/%


:CLEAN-UP
IF EXIST %PARENT%\nharulib.mak (
	ECHO %ME%: Old configuration clean-up...
	NMAKE /NOLOGO /F %PARENT%\nharulib.mak distclean
	IF %ERRORLEVEL% NEQ 0 (
		ECHO %ME%: Could not cleanup existing configuration
		EXIT /B %ERRORLEVEL%
	)
	DEL %PARENT%\nharulib.mak
)
IF EXIST %PARENT%\src\nharu.mak ( DEL %PARENT%\src\nharu.mak )
IF EXIST %PARENT%\jca\native\nharujca.mak ( DEL %PARENT%\jca\native\nharujca.mak )


:DEPENDECY_SEARCH
IF NOT DEFINED OPENSSL (
	ECHO %ME%: Searching for OpenSSL...
	CALL:INSTALL_FOLDER opensslconf.h,%ROOT%,OPENSSL
	IF NOT DEFINED OPENSSL (
		ECHO %ME%: OpenSSL search failure
		EXIT /B 2
	)
)
FOR /F %%i IN ('dirname %OPENSSL%') DO SET OPENSSL=%%i
SET OPENSSL=%OPENSSL:/=\%
ECHO %ME%: OpenSSL found at %OPENSSL%

IF NOT DEFINED LIBIDN (
	ECHO %ME%: Searching for GNU IDN Library...
	CALL:INSTALL_FOLDER stringprep.h,%ROOT%,LIBIDN
	IF NOT DEFINED LIBIDN (
		ECHO %ME%: GNU IDN Library search failure
		EXIT /B 2
	)
)
SET LIBIDN=%LIBIDN:/=\%
ECHO %ME%: GNU IDN Library found at %LIBIDN%

IF NOT DEFINED JAVA_HOME (
	ECHO %ME%: Searching for JDK instalation...
	CALL:GET_JAVA_HOME JAVA_HOME
	IF NOT DEFINED JAVA_HOME (
		ECHO JDK not properly installed
		EXIT /B 2
	)
)
ECHO %ME%: JDK found at "%JAVA_HOME%"

IF NOT DEFINED _JRE_7_ (
	ECHO %ME%: Searching for JRE 7 runtime...
	CALL:FIND_TARGET rt.jar,%ROOT%,__ARG
)
IF DEFINED __ARG (
	ECHO DEFINED %__ARG% 
	SET _JRE_7_=%__ARG%
)
IF NOT DEFINED _JRE_7_ (
	IF NOT DEFINED JAVA_HOME (
		ECHO %ME%: Java 7 runtime search failure
		EXIT /B 2
	)
	SET _JRE_7_="%JAVA_HOME%\jre\lib\rt.jar"
)
ECHO %ME%: Java 7 runtime found at %_JRE_7_%


IF NOT DEFINED ANT_HOME (
	ECHO %ME%: Searching for Apache Ant...
	CALL:INSTALL_FOLDER ant.bat,%ROOT%,ANT_HOME
	IF NOT DEFINED ANT_HOME (
		ECHO %ME%: Apache Ant search failure
		EXIT /B 2
	)
)
SET ANT_HOME=%ANT_HOME:/=\%
ECHO %ME%: Apache Ant found at %ANT_HOME%

IF NOT DEFINED ANT_CONTRIB (
	ECHO %ME%: Searching for Ant-contrib library...
	CALL:FIND_JAR ant-contrib-*.jar,%ROOT%,ANT_CONTRIB
	IF NOT DEFINED ANT_CONTRIB (
		ECHO %ME%: Apache Ant search failure
		EXIT /B 2
	)
)
SET ANT_CONTRIB=%ANT_CONTRIB:/=\%
ECHO %ME%: Ant-contrib library found at %ANT_CONTRIB%

IF NOT DEFINED INCLUDE (
	ECHO %ME%: Windows SDK environment not found
	EXIT /B 3
)
SET _SDK_INCLUDE_=/I"%INCLUDE:;=" /I"%"
SET _SDK_INCLUDE_=%_SDK_INCLUDE_:/I""=%


:GEN_NHARU_MAK	
ECHO %ME%: Generating static library makefile
SET INCLUDE_LIST=%OPENSSL%\include,%LIBIDN%\include
SET _APP_INCLUDE_=/I"%INCLUDE_LIST:,=" /I"%"
SET _APP_INCLUDE_=%_APP_INCLUDE_:/I""=%

ECHO # * * * * * * * * * * * * * * * * * * * * * * * * * *>MAKEFILE.W
ECHO # Windows makefile for nharu static library>>MAKEFILE.W
ECHO # Copyleft 2016 by The Crypthing Initiative>>MAKEFILE.W
ECHO # Generated by %ME%>>MAKEFILE.W
ECHO # Do not edit it unless you know what you are doing>>MAKEFILE.W
ECHO # * * * * * * * * * * * * * * * * * * * * * * * * * *>>MAKEFILE.W
FOR /F "tokens=* delims=;" %%i IN (%CUR%nharu.mak.in) DO (
	SET LINE=%%i
	SET LINE=!LINE:_SOURCE_=%PARENT%!
	SET LINE=!LINE:_PREFIX_=%_PREFIX_%!
	SET LINE=!LINE:_APP_INCLUDE_=%_APP_INCLUDE_%!
	SET LINE=!LINE:_SDK_INCLUDE_=%_SDK_INCLUDE_%!
	SET LINE=!LINE:_CVARS_=%_CVARS_%!
	SET LINE=!LINE:_CFLAGS_=%_CFLAGS_%!
	SET LINE=!LINE:_LFLAGS_=%_LFLAGS_%!
	ECHO !LINE!>>MAKEFILE.W
)
IF %ERRORLEVEL% NEQ 0 (
	ECHO %ME%: Could not generate nharu.lib nmake file
	DEL MAKEFILE.W
	EXIT /B 4
)
PERL -pe "s/,/\n/g" MAKEFILE.W>%PARENT%\src\nharu.mak
IF %ERRORLEVEL% NEQ 0 (
	ECHO %ME%: Could not generate nharu.lib nmake file
	DEL MAKEFILE.W
	EXIT /B 4
)
DEL MAKEFILE.W


:GEN_JCA_DLL
ECHO %ME%: Generating JCA shared library makefile
SET INCLUDE_LIST=%OPENSSL%\include,%LIBIDN%\include,%JAVA_HOME%\include,%JAVA_HOME%\include\win32
SET _APP_INCLUDE_=/I"%INCLUDE_LIST:,=" /I"%"
SET _APP_INCLUDE_=%_APP_INCLUDE_:/I""=%
SET _LIBIDN_=%LIBIDN%\lib
SET _OPENSSL_=%OPENSSL%\lib
SET _NHARU_=%PARENT%\src

ECHO # * * * * * * * * * * * * * * * * * * * * * * * * * *>MAKEFILE.W
ECHO # Windows makefile for nharu JCA shared library>>MAKEFILE.W
ECHO # Copyleft 2016 by The Crypthing Initiative>>MAKEFILE.W
ECHO # Generated by %ME%>>MAKEFILE.W
ECHO # Do not edit it unless you know what you are doing>>MAKEFILE.W
ECHO # * * * * * * * * * * * * * * * * * * * * * * * * * *>>MAKEFILE.W
FOR /F "tokens=* delims=;" %%i IN (%CUR%nharujca.mak.in) DO (
	SET LINE=%%i
	SET LINE=!LINE:_SOURCE_=%PARENT%!
	SET LINE=!LINE:_PREFIX_=%_PREFIX_%!
	SET LINE=!LINE:_APP_INCLUDE_=%_APP_INCLUDE_%!
	SET LINE=!LINE:_SDK_INCLUDE_=%_SDK_INCLUDE_%!
	SET LINE=!LINE:_CFLAGS_=%_CFLAGS_%!
	SET LINE=!LINE:_CVARS_=%_CVARS_%!
	SET LINE=!LINE:_LFLAGS_=%_JCAFLAGS_%!
	SET LINE=!LINE:_LIBIDN_=%_LIBIDN_%!
	SET LINE=!LINE:_OPENSSL_=%_OPENSSL_%!
	SET LINE=!LINE:_NHARU_=%_NHARU_%!
	ECHO !LINE!>>MAKEFILE.W
)
IF %ERRORLEVEL% NEQ 0 (
	ECHO %ME%: Could not generate nharujca.dll nmake file
	DEL MAKEFILE.W
	EXIT /B 4
)
PERL -pe "s/,/\n/g" MAKEFILE.W>%PARENT%\jca\native\nharujca.mak
IF %ERRORLEVEL% NEQ 0 (
	ECHO %ME%: Could not generate nharujca.dll nmake file
	DEL MAKEFILE.W
	EXIT /B 4
)
DEL MAKEFILE.W


:GEN_MAKE_ALL
ECHO %ME%: Generating global makefile
SET _PREFIX_=%_PREFIX_%\/libs
ECHO # * * * * * * * * * * * * * * * * * * * * * * * * * *>MAKEFILE.W
ECHO # Windows makefile for all nharu libraries>>MAKEFILE.W
ECHO # Copyleft 2016 by The Crypthing Initiative>>MAKEFILE.W
ECHO # Generated by %ME%>>MAKEFILE.W
ECHO # Do not edit it unless you know what you are doing>>MAKEFILE.W
ECHO # * * * * * * * * * * * * * * * * * * * * * * * * * *>>MAKEFILE.W
FOR /F "tokens=* delims=;" %%i IN (%CUR%nharulib.mak.in) DO (
	SET LINE=%%i
	SET LINE=!LINE:_ANT_CONTRIB_=%ANT_CONTRIB%!
	SET LINE=!LINE:_PACKAGE_=%PARENT%!
	SET LINE=!LINE:_PREFIX_=%_PREFIX_%!
	SET LINE=!LINE:_ANT_HOME_=%ANT_HOME%!
	SET LINE=!LINE:_JRE_7_=%_JRE_7_%!
	ECHO !LINE!>>MAKEFILE.W
)
IF %ERRORLEVEL% NEQ 0 (
	ECHO %ME%: Could not generate Nharu libraries nmake file
	DEL MAKEFILE.W
	EXIT /B 4
)
PERL -pe "s/,/\n/g" MAKEFILE.W>%PARENT%\nharulib.mak
IF %ERRORLEVEL% NEQ 0 (
	ECHO %ME%: Could not generate Nharu libraries nmake file
	DEL MAKEFILE.W
	EXIT /B 4
)
DEL MAKEFILE.W


:FINALLY
ECHO * * * * * * * * * * * * * * * * * * * * * *
ECHO * Nharu libraries configuration complete! *
ECHO * * * * * * * * * * * * * * * * * * * * * *
ECHO.
GOTO:DONE


:GET_ARGS
:: PROCESS COMAND LINE ARGUMENT OF TYPE --arg=value
:: %~1: ARGUMENT MARKER (USUALY --)
:: %~2: OUT
ECHO.%~2 | FINDSTR /C:"%~1" 1>nul
IF NOT errorlevel 1 (
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


:INSTALL_FOLDER
:: SEARCH FOR DEPENDENCY LIBRARY INSTALL DIRECTORY
:: %~1: FILE TO SEARCH
:: %~2: FOLDER WHERE THE SEARCH SHOULD START
:: %~3: OUT
FOR /F %%i IN ('find %~2 -name %~1 -printf ^"%%T@ %%p\n^" ^| sort -n ^| tail -1 ^| cut -f2- -d^" ^"') DO SET __TARGET=%%i
IF "%__TARGET%" EQU "" ( GOTO:EOF )
FOR /F %%i IN ('dirname %__TARGET%') DO SET __TARGET=%%i
FOR /F %%i IN ('dirname %__TARGET%') DO SET __TARGET=%%i
SET %~3=%__TARGET%
SET __TARGET=
GOTO:EOF

:FIND_TARGET
FOR /F %%i IN ('find %~2 -name %~1 -printf ^"%%T@ %%p\n^" ^| sort -n ^| tail -1 ^| cut -f2- -d^" ^"') DO SET __TARGET=%%i
IF "%__TARGET%" EQU "" ( GOTO:EOF )
SET %~3=%__TARGET%
SET __TARGET=
GOTO:EOF

:GET_JAVA_HOME
:: SEARCH FOR JAVA_HOME FOLDER
:: %~1: OUT
FOR /F %%i IN ('which java ^| PERL -pe ^"s/\n//g^"') DO SET __HOME=%%i
IF %ERRORLEVEL% NEQ 0 ( GOTO:EOF )
IF "%__HOME%" EQU ""  (	GOTO:EOF )
FOR /F %%i IN ('dirname %__HOME%') DO SET __HOME=%%i
FOR /F %%i IN ('dirname %__HOME%') DO SET __HOME=%%i
IF NOT EXIST %__HOME%\include\win32\jni_md.h ( GOTO:EOF )
SET %~1=%__HOME%
SET __HOME=
GOTO:EOF

:FIND_JAR
:: SEARCH FOR JAR INSTALL DIRECTORY
:: %~1: JAR TO FIND
:: %~2: FOLDER WHERE THE SEARCH SHOULD START
:: %~3: OUT
FOR /F %%i IN ('find %~2 -name %~1 -printf ^"%%T@ %%p\n^" ^| sort -n ^| tail -1 ^| cut -f2- -d^" ^"') DO SET __TARGET=%%i
IF "%__TARGET%" EQU "" ( GOTO:EOF )
SET %~3=%__TARGET%
SET __TARGET=
GOTO:EOF


:USAGE
ECHO.
ECHO * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
ECHO Usage: %ME% [options]
ECHO * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
ECHO --prefix: install base directory. Default value: %_PREFIX_%.
ECHO --cvars: compiler variables definitions by -D. Default value: %_CVARS_%.
ECHO --cflags: compiler flags. Default value: %_CFLAGS_%.
ECHO --lflags: librarian flags. Default value: %_LFLAGS_%.
ECHO --jcaflags: linker flagas. Default value: %_JCAFLAGS_%
ECHO --openssl: OpenSSL install directory. By default it is searched from %ROOT%.
ECHO --libidn: GNU Libidn install directory. By default it is searched from %ROOT%.
ECHO --java: JDK install directory. Default value: "%JAVA_HOME%".
ECHO --jre: Java 7 runtime directory. By default it is searched from %ROOT%.
ECHO --ant: Apache Ant install directory. By default it is searched from %ROOT%.
ECHO --ant-contrib: Ant Contrib Tasks install directory. By default it is searched from %ROOT%.
ECHO.

:DONE
ENDLOCAL
