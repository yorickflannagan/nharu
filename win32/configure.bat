@ECHO OFF
SETLOCAL EnableExtensions
SETLOCAL EnableDelayedExpansion

ECHO.
ECHO * * * * * * * * * * * * * * * * *
ECHO * Nharu libraries configuration *
ECHO * * * * * * * * * * * * * * * * *

:STARTUP
SET ME=%~n0
SET CUR=%~dp0
FOR /F %%i IN ('dirname %CUR%') DO SET PARENT=%%i
SET _PREFIX_=%PARENT%\libs
SET _OUTPUT_=%~dp0---***---
SET _OUTPUT_=%_OUTPUT_:\---***---=%
SET _CVARS_=-DWIN32 -D_WIN32 -D_UNICODE -DUNICODE
SET _CDEBUG_=/GL /analyze-
SET _CFLAGS_=/TC /Gy /O2 /Zc:wchar_t /Gm- /WX- /Gd /Ot /c
SET _LFLAGS_=/LTCG /NOLOGO
FOR %%a IN (%*) DO (
    CALL:GET_ARGS "--","%%a" 
)
IF DEFINED --help (
	GOTO USAGE
)
IF DEFINED --prefix (
	SET _PREFIX_=%--prefix%
)
IF DEFINED --cvars (
	SET _CVARS_=%--cvars%
)
IF DEFINED --cdebug (
	SET _CDEBUG_= %--cdebug%
)
IF DEFINED --cflags (
	SET _CFLAGS_=%--cflags%
)
IF DEFINED --lflags (
	SET _LFLAGS_=%--lflags%
)
IF DEFINED --openssl (
	IF NOT EXIST %--openssl%\lib\libeay32.lib (
		ECHO %ME%: --openssl argument does not point to OpenSSL install directory
		EXIT /B 1
	)
	SET OPENSSL=%--openssl%
)
IF DEFINED --libidn (
	IF NOT EXIST %--libidn%\lib\libidn.lib (
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
REM Required by GNU mkdir
SET _PREFIX_=%_PREFIX_:\=\/%
CALL:CLEANUP nharu.mak "%PARENT%\src"
IF %ERRORLEVEL% NEQ 0 (
	EXIT /B %ERRORLEVEL%
)
CALL:CLEANUP nharujca.mak "%PARENT%\jca\native"
IF %ERRORLEVEL% NEQ 0 (
	EXIT /B %ERRORLEVEL%
)


:DEPENDECY_SEARCH
IF NOT DEFINED OPENSSL (
	ECHO %ME%: Searching for OpenSSL...
	CALL:INSTALL_FOLDER libeay32.lib,%PARENT%,OPENSSL
	IF NOT DEFINED OPENSSL (
		ECHO %ME%: OpenSSL search failure
		EXIT /B 1
	)
)
SET OPENSSL=%OPENSSL:/=\%
IF NOT EXIST %OPENSSL%\include\openssl\opensslconf.h (
	ECHO %ME%: Incorrect OpenSSL %OPENSSL% install directory
	EXIT /B 1
)
ECHO %ME%: OpenSSL found at %OPENSSL%
SET _LFLAGS_=%_LFLAGS_% /LIBPATH:"%OPENSSL%\lib"

IF NOT DEFINED LIBIDN (
	ECHO %ME%: Searching for GNU IDN Library...
	CALL:INSTALL_FOLDER libidn.lib,%PARENT%,LIBIDN
	IF NOT DEFINED LIBIDN (
		ECHO %ME%: GNU IDN Library search failure
		EXIT /B 1
	)
)
SET LIBIDN=%LIBIDN:/=\%
IF NOT EXIST %LIBIDN%\include\stringprep.h (
	ECHO %ME%: Incorrect GNU IDN Library %LIBIDN% install directory
	EXIT /B 1
)
SET _LFLAGS_=%_LFLAGS_% /LIBPATH:"%LIBIDN%\lib"
ECHO %ME%: GNU IDN Library found at %LIBIDN%

IF NOT DEFINED JAVA_HOME (
	ECHO %ME%: Searching for JDK instalation...
	CALL:GET_JAVA_HOME JAVA_HOME
	IF NOT DEFINED JAVA_HOME (
		ECHO JDK not properly installed
		EXIT /B 1
	)
)
ECHO %ME%: JDK found at %JAVA_HOME%

IF NOT DEFINED ANT_HOME (
	ECHO %ME%: Searching for Apache Ant...
	CALL:GET_ANT_HOME %PARENT%,ANT_HOME
	IF NOT DEFINED ANT_HOME (
		ECHO %ME%: Apache Ant search failure
		EXIT /B 1
	)
)
SET ANT_HOME=%ANT_HOME:/=\%
ECHO %ME%: Apache Ant found at %ANT_HOME%

IF NOT DEFINED ANT_CONTRIB (
	ECHO %ME%: Searching for Ant-contrib library...
	CALL:FIND_JAR ant-contrib.jar,%PARENT%,ANT_CONTRIB
	IF NOT DEFINED ANT_CONTRIB (
		ECHO %ME%: Apache Ant search failure
		EXIT /B 1
	)
)
SET ANT_CONTRIB=%ANT_CONTRIB:/=\%
ECHO %ME%: Ant-contrib library found at %ANT_CONTRIB%

ECHO %ME%: Searching for JEE crl-service library dependency...
CALL:FIND_JAR javaee-api-*.jar,%CUR%,JEE_LIB
IF NOT DEFINED JEE_LIB (
	ECHO %ME%: JEE crl-service library search failure
	EXIT /B 1
)
SET JEE_LIB=%JEE_LIB:/=\%
ECHO %ME%: JEE crl-service library found at %JEE_LIB%

ECHO %ME%: Searching for JBoss crl-service library dependency...
CALL:FIND_JAR picketbox-*.jar,%CUR%,PICKETBOX
IF NOT DEFINED PICKETBOX (
	ECHO %ME%: JBoss crl-service library search failure
	EXIT /B 1
)
SET PICKETBOX=%PICKETBOX:/=\%
ECHO %ME%: JBoss crl-service library found at %PICKETBOX%


IF NOT DEFINED INCLUDE (
	ECHO %ME%: Windows SDK environment not found
	EXIT /B 1
)
SET _SDK_INCLUDE_=/I"%INCLUDE:;=" /I"%"
SET _SDK_INCLUDE_=%_SDK_INCLUDE_:/I""=%

:GEN_NHARU_MAK
ECHO %ME%: Capturing nharu.lib source files...
SET _CVARS_=%_CVARS_% -D_LIB
CALL:LISTSOURCES "%PARENT%\src" SOURCE_LIST
IF NOT DEFINED SOURCE_LIST (
	ECHO %ME%: Could not list nharu source files
	EXIT /B 1
)
SET _SOURCE_FILES_=%SOURCE_LIST:,= \,%
SET GREP_LIST=%PARENT%\include,%PARENT%\pkcs11,%PARENT%\src
SET INCLUDE_LIST=%GREP_LIST%,%OPENSSL%\include,%LIBIDN%\include
FOR %%i IN (%INCLUDE_LIST%) DO (
	SET _APP_INCLUDE_=!_APP_INCLUDE_! /I"%%i"
)
ECHO # * * * * * * * * * * * * * * * * * * * * * * * * * *>MAKEFILE.W
ECHO # Windows makefile for nharu static library>>MAKEFILE.W
ECHO # Copyleft 2016 by The Crypthing Initiative>>MAKEFILE.W
ECHO # Generated by %ME%>>MAKEFILE.W
ECHO # Do not edit it unless you know what you are doing>>MAKEFILE.W
ECHO # * * * * * * * * * * * * * * * * * * * * * * * * * *>>MAKEFILE.W
FOR /F "tokens=* delims=;" %%i IN (%CUR%nharu.mak.in) DO (
	SET LINE=%%i
	SET LINE=!LINE:_PREFIX_=%_PREFIX_%!
	SET LINE=!LINE:_OUTPUT_=%_OUTPUT_%!
	SET LINE=!LINE:_APP_INCLUDE_=%_APP_INCLUDE_%!
	SET LINE=!LINE:_SDK_INCLUDE_=%_SDK_INCLUDE_%!
	SET LINE=!LINE:_SOURCE_FILES_=%_SOURCE_FILES_%!
	SET LINE=!LINE:_CVARS_=%_CVARS_%!
	SET LINE=!LINE:_CDEBUG_=%_CDEBUG_%!
	SET LINE=!LINE:_CFLAGS_=%_CFLAGS_%!
	SET LINE=!LINE:_LFLAGS_=%_LFLAGS_%!
	ECHO !LINE!>>MAKEFILE.W
)
IF %ERRORLEVEL% NEQ 0 (
	ECHO %ME%: Could not generate nharu.lib nmake file
	DEL MAKEFILE.W
	EXIT /B 1
)
perl -pe "s/,/\n/g" MAKEFILE.W>%PARENT%\src\nharu.mak
IF %ERRORLEVEL% NEQ 0 (
	ECHO %ME%: Could not generate nharu.lib nmake file
	DEL MAKEFILE.W
	EXIT /B 1
)
DEL MAKEFILE.W
SET SOURCE_LIST=
SET _SOURCE_FILES_=
SET GREP_LIST=
SET INCLUDE_LIST=
SET _APP_INCLUDE_=

:GEN_JCA_DLL
SET _CVARS_=%_CVARS_% -D_WINDOWS -D_USRDLL -DNHARUJCA_EXPORTS
SET _LFLAGS_=%_LFLAGS_% /LIBPATH:"%_OUTPUT_%" /DLL /OPT:REF /INCREMENTAL:NO
ECHO %ME%: Capturing nharujca.dll source files...
CALL:LISTSOURCES "%PARENT%\jca\native" SOURCE_LIST
IF NOT DEFINED SOURCE_LIST (
	ECHO %ME%: Could not list nharu jca source files
	EXIT /B 1
)
SET _VERSION_C_=%PARENT%\jca\native\version.c
SET SOURCE_LIST=%_VERSION_C_%,%SOURCE_LIST%
SET _SOURCE_FILES_=%SOURCE_LIST:,= \,%
SET GREP_LIST=%PARENT%\include,%PARENT%\pkcs11,%PARENT%\jca\native
SET INCLUDE_LIST=%GREP_LIST%,%OPENSSL%\include,%LIBIDN%\include,%JAVA_HOME%\include,%JAVA_HOME%\include\win32
FOR %%i IN (%INCLUDE_LIST%) DO (
	SET _APP_INCLUDE_=!_APP_INCLUDE_! /I"%%i"
)
ECHO # * * * * * * * * * * * * * * * * * * * * * * * * * *>MAKEFILE.W
ECHO # Windows makefile for nharu JCA shared library>>MAKEFILE.W
ECHO # Copyleft 2016 by The Crypthing Initiative>>MAKEFILE.W
ECHO # Generated by %ME%>>MAKEFILE.W
ECHO # Do not edit it unless you know what you are doing>>MAKEFILE.W
ECHO # * * * * * * * * * * * * * * * * * * * * * * * * * *>>MAKEFILE.W
FOR /F "tokens=* delims=;" %%i IN (%CUR%nharujca.mak.in) DO (
	SET LINE=%%i
	SET LINE=!LINE:_PREFIX_=%_PREFIX_%!
	SET LINE=!LINE:_OUTPUT_=%_OUTPUT_%!
	SET LINE=!LINE:_APP_INCLUDE_=%_APP_INCLUDE_%!
	SET LINE=!LINE:_SDK_INCLUDE_=%_SDK_INCLUDE_%!
	SET LINE=!LINE:_SOURCE_FILES_=%_SOURCE_FILES_%!
	SET LINE=!LINE:_CVARS_=%_CVARS_%!
	SET LINE=!LINE:_CDEBUG_=%_CDEBUG_%!
	SET LINE=!LINE:_CFLAGS_=%_CFLAGS_%!
	SET LINE=!LINE:_LFLAGS_=%_LFLAGS_%!
	SET LINE=!LINE:_VERSION_C_=%_VERSION_C_%!
	ECHO !LINE!>>MAKEFILE.W
)
IF %ERRORLEVEL% NEQ 0 (
	ECHO %ME%: Could not generate nharujca.dll nmake file
	DEL MAKEFILE.W
	EXIT /B 1
)
perl -pe "s/,/\n/g" MAKEFILE.W>%PARENT%\jca\native\nharujca.mak
IF %ERRORLEVEL% NEQ 0 (
	ECHO %ME%: Could not generate nharujca.dll nmake file
	DEL MAKEFILE.W
	EXIT /B 1
)
DEL MAKEFILE.W

:GEN_MAKE_ALL
SET _PREFIX_=%_PREFIX_:\/=\%
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
	SET LINE=!LINE:_LIBIDN_=%LIBIDN%!
	SET LINE=!LINE:_ANT_HOME_=%ANT_HOME%!
	SET LINE=!LINE:_JEE_LIB_=%JEE_LIB%!
	SET LINE=!LINE:_PICKETBOX_=%PICKETBOX%!
	ECHO !LINE!>>MAKEFILE.W
)
IF %ERRORLEVEL% NEQ 0 (
	ECHO %ME%: Could not generate Nharu libraries nmake file
	DEL MAKEFILE.W
	EXIT /B 1
)
perl -pe "s/,/\n/g" MAKEFILE.W>%PARENT%\nharulib.mak
IF %ERRORLEVEL% NEQ 0 (
	ECHO %ME%: Could not generate Nharu libraries nmake file
	DEL MAKEFILE.W
	EXIT /B 1
)
DEL MAKEFILE.W

ECHO.
ECHO %ME%: Nharu libraries configuration complete!
GOTO DONE


:GET_ARGS
REM PROCESS COMAND LINE ARGUMENT OF TYPE --arg=value
REM %~1: ARGUMENT MARKER (USUALY --)
REM %~2: OUT
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

:CLEANUP
REM CLEAN-UP SPECIFIED MAKE
REM %~1: NMAKE FILE NAME
REM %~2: TARGET NMAKE FILE DIRECTORY
SET __NMAKE=%~1
SET __TARGET=%~2
IF NOT EXIST %~dp0%__NMAKE%.in (
	ECHO %ME%: Makefile %__NMAKE%.in not found
	EXIT /B 1
)
IF EXIST %__TARGET%\%__NMAKE% (
	ECHO %ME%: Old configuration clean-up...
	nmake /NOLOGO NODEBUG=1 /f %__TARGET%\%__NMAKE% clean
	IF %ERRORLEVEL% NEQ 0 (
		ECHO %ME%: Could not cleanup existing configuration
		EXIT /B %ERRORLEVEL%
	)
	rm %__TARGET%\%__NMAKE%
	IF %ERRORLEVEL% NEQ 0 (
		ECHO %ME%: Could not cleanup existing configuration
		EXIT /B %ERRORLEVEL%
	)
)
SET __NMAKE=
SET __TARGET=
GOTO:EOF


:LISTSOURCES
REM LIST C FILES UNDER SPECIFIED DIRECTORY
REM %~1: DIRECTORY TO LIST
REM %~2: OUT
SET __LIST=---***---
FOR /F %%a IN ('FORFILES /P %~1 /S /M *.c') DO (
	SET __LIST=!__LIST!,%~1\%%a
)
IF %ERRORLEVEL% NEQ 0 (
	GOTO:EOF
)
SET __LIST=!__LIST:"=!
SET __LIST=!__LIST:---***---,=!
SET %~2=%__LIST%
SET __LIST=
GOTO:EOF

:INSTALL_FOLDER
REM SEARCH FOR DEPENDENCY LIBRARY INSTALL DIRECTORY
REM %~1: FILE TO SEARCH
REM %~2: FOLDER WHERE THE SEARCH SHOULD START
REM %~3: OUT
FOR /F %%i IN ('find %~2 -name %~1 -printf ^"%%T@ %%p\n^" ^| sort -n ^| tail -1 ^| cut -f2- -d^" ^"') DO SET __TARGET=%%i
IF "%__TARGET%" EQU "" (
	GOTO:EOF
)
FOR /F %%i IN ('dirname %__TARGET%') DO SET __TARGET=%%i
FOR /F %%i IN ('dirname %__TARGET%') DO SET __TARGET=%%i
SET %~3=%__TARGET%
SET __TARGET=
GOTO:EOF


:GET_JAVA_HOME
REM SEARCH FOR JAVA_HOME FOLDER
REM %~1: OUT
FOR /F %%i IN ('which java ^| perl -pe ^"s/\n//g^"') DO SET __HOME=%%i
IF %ERRORLEVEL% NEQ 0 (
	GOTO:EOF
)
IF "%__HOME%" EQU ""  (
	GOTO:EOF
)
FOR /F %%i IN ('dirname %__HOME%') DO SET __HOME=%%i
FOR /F %%i IN ('dirname %__HOME%') DO SET __HOME=%%i
IF NOT EXIST %__HOME%\include\win32\jni_md.h (
	GOTO:EOF
)
SET %~1=%__HOME%
SET __HOME=
GOTO:EOF

:GET_ANT_HOME
REM SEARCH FOR APACHE ANT INSTALL DIRECTORY
REM %~1: FOLDER WHERE THE SEARCH SHOULD START
REM %~2: OUT
FOR /F %%i IN ('dirname %~1') DO SET __FROM=%%i
IF "%__FROM%" EQU ""  (
	GOTO:EOF
)
CALL:INSTALL_FOLDER ant.bat,"%__FROM%",__OUT
SET %~2=%__OUT%
SET __OUT=
SET __FROM=
GOTO:EOF

:FIND_JAR
REM SEARCH FOR ANT-CONTRIB INSTALL DIRECTORY
REM %~1: JAR TO FIND
REM %~2: FOLDER WHERE THE SEARCH SHOULD START
REM %~3: OUT
FOR /F %%i IN ('dirname %~2') DO SET __FROM=%%i
IF "%__FROM%" EQU ""  (
	GOTO:EOF
)
FOR /F %%i IN ('find %__FROM% -name %~1 -printf ^"%%T@ %%p\n^" ^| sort -n ^| tail -1 ^| cut -f2- -d^" ^"') DO SET __TARGET=%%i
IF "%__TARGET%" EQU "" (
	GOTO:EOF
)
SET %~3=%__TARGET%
SET __FROM=
SET __TARGET=
GOTO:EOF


:USAGE
REM TODO
:DONE
ENDLOCAL
