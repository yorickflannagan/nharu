@ECHO off
REM * * * * * * * * * * * * * * * * * * * * * * * * *
REM GNU IDN Library for Windows configuration script
REM Copyleft 2016 by The Crypthing Initiative
REM * * * * * * * * * * * * * * * * * * * * * * * * *
REM Make sure the following steps were done prior to run this script:
REM 1. Install GnuWin (http://gnuwin32.sourceforge.net/)
REM 2. Install ActivePearl (http://www.activestate.com/activeperl)
REM 3. Install Windows SDK (at least version 7.1)
REM 4. Clone git://git.savannah.gnu.org/libidn.git and checkout libidn-1-32
REM 5. Execute under SDK command line environment
REM * * * * * * * * * * * * * * * * * * * * * * * * *
SETLOCAL EnableExtensions
SETLOCAL EnableDelayedExpansion

ECHO.
ECHO * * * * * * * * * * * * * * * * * * * * * * *
ECHO * GNU IDN Library for Windows configuration *
ECHO * * * * * * * * * * * * * * * * * * * * * * *

:CMD_LINE
SET ME=%~n0
SET CUR=%~dp0
FOR /F %%i IN ('dirname %CUR%') DO SET PARENT=%%i
SET _PREFIX_=%PARENT%\3rdparty\idn
SET _SOURCE_=%USERPROFILE%\dev\libidn
SET _CVARS_=-DWIN32 -D_WIN32 -DIDNA_EXPORTS -DHAVE_CONFIG_H -D_CRT_SECURE_NO_DEPRECATE -D_CRT_NONSTDC_NO_DEPRECATE -D_MBCS -D_LIB
SET _CDEBUG_=/GL /analyze-
SET _CFLAGS_=/TC /Gy /O2 /Zc:wchar_t /Gm- /WX- /Gd /Ot /c
SET _LFLAGS_=/LTCG /NOLOGO
SET _IMPLIBS_="kernel32.lib" "user32.lib" "gdi32.lib" "winspool.lib" "comdlg32.lib" "advapi32.lib" "shell32.lib" "ole32.lib" "oleaut32.lib" "uuid.lib" "odbc32.lib" "odbccp32.lib"

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
IF DEFINED --source  (
	SET _SOURCE_=%--source%
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
IF DEFINED --implibs (
	SET _IMPLIBS_=%--implibs%
)
REM Required by GNU mkdir
SET _PREFIX_=%_PREFIX_:\=\/%

:VARS
ECHO %ME%: Finding GNU IDN Library...
IF NOT EXIST %CUR%libidn.mak.in (
	ECHO %ME%: Makefile for GNU IDN Library not found
	EXIT /B 1
)
IF NOT EXIST %CUR%win32.mak (
	ECHO %ME%: Makefile for Win32 not found
	EXIT /B 1
)
IF NOT EXIST %CUR%ac-stdint.h.in (
	ECHO %ME%:  ac-stdint.h replace file not found
	EXIT /B 1
)
IF NOT EXIST %_SOURCE_%\windows\libidn.sln (
	ECHO %ME%:  GNU Libidn source code not found
	EXIT /B 1
)
SET _WINPACK_=%_SOURCE_%\windows
SET _SDK_INCLUDE_=/I"%INCLUDE:;=" /I"%"
SET _SDK_INCLUDE_=%_SDK_INCLUDE_:/I""=%

:CLEANUP
IF EXIST %PARENT%\libidn.mak (
	ECHO %MW%: Old configuration clean-up...
	nmake /NOLOGO NODEBUG=1 /f %PARENT%\libidn.mak clean
	IF %ERRORLEVEL% NEQ 0 (
		ECHO %ME%: Could not cleanup existing configuration
		EXIT /B %ERRORLEVEL%
	)
	rm %PARENT%\libidn.mak
	IF %ERRORLEVEL% NEQ 0 (
		ECHO %ME%: Could not cleanup existing configuration
		EXIT /B %ERRORLEVEL%
	)
	rm %PARENT%/win32.mak
)

:GENRFC
IF NOT EXIST "%_SOURCE_%/lib/rfc3454.c" (
	ECHO %ME%: Generating rfc3454 data...
	CD %_SOURCE_%/lib
	perl gen-stringprep-tables.pl ../doc/specifications/rfc3454.txt
	IF %ERRORLEVEL% NEQ 0 (
		ECHO %ME%: Could not generate rfc3454.c file
		CD %CUR%
		EXIT /B %ERRORLEVEL%
	)
	CD %CUR%
)

:GENTLD
FOR /F %%i IN ('ls %_SOURCE_%/doc/tld/*.tld') DO (
	SET __CMD_ARGS=!__CMD_ARGS! %%i
)
IF NOT EXIST "%_SOURCE_%/lib/tlds.c" (
	ECHO %ME%: Generating TLD data...
	IF "%__CMD_ARGS%" EQU "" (
		ECHO %ME%: Could not find input files
		EXIT /B 1
	)
	perl %_SOURCE_%/lib/gen-tld-tables.pl %__CMD_ARGS%>%_SOURCE_%/lib/tlds.c
	IF %ERRORLEVEL% NEQ 0 (
		ECHO %ME%: Could not generate tlds.c file
		EXIT /B %ERRORLEVEL%
	)
)

:ADJUST
IF NOT EXIST "%_SOURCE_%/lib/gl/unistr.h" (
	cp %_SOURCE_%/lib/gl/unistr.in.h %_SOURCE_%/lib/gl/unistr.h
)
IF NOT EXIST "%_SOURCE_%/lib/gl/unitypes.h" (
	cp %_SOURCE_%/lib/gl/unitypes.in.h %_SOURCE_%/lib/gl/unitypes.h
)
IF NOT EXIST "%_SOURCE_%/lib/gl/unused-parameter.h" (
	cp %_SOURCE_%/build-aux/snippet/unused-parameter.h %_SOURCE_%/lib/gl/unused-parameter.h
)
cp %CUR%ac-stdint.h.in %_WINPACK_%/include/ac-stdint.h
cp %CUR%win32.mak %PARENT%/win32.mak

:GENMAK
ECHO # * * * * * * * * * * * * * * * * * * * * * * * * * *>%PARENT%\libidn.mak
ECHO # Copyleft 2016 by The Crypthing Initiative>>%PARENT%\libidn.mak
ECHO # Makefile generated by %ME%>>%PARENT%\libidn.mak
ECHO # Do not edit it unless you know what you are doing>>%PARENT%\libidn.mak
ECHO # * * * * * * * * * * * * * * * * * * * * * * * * * *>>%PARENT%\libidn.mak
FOR /F "tokens=* delims=," %%i IN (%CUR%libidn.mak.in) DO (
	SET LINE=%%i
	SET LINE=!LINE:_PREFIX_=%_PREFIX_%!
	SET LINE=!LINE:_PACKAGE_=%_SOURCE_%!
	SET LINE=!LINE:_WINPACK_=%_WINPACK_%!
	SET LINE=!LINE:_SDK_INCLUDE_=%_SDK_INCLUDE_%!
	SET LINE=!LINE:_CVARS_=%_CVARS_%!
	SET LINE=!LINE:_CDEBUG_=%_CDEBUG_%!
	SET LINE=!LINE:_CFLAGS_=%_CFLAGS_%!
	SET LINE=!LINE:_LFLAGS_=%_LFLAGS_%!
	SET LINE=!LINE:_IMPLIBS_=%_IMPLIBS_%!
	ECHO !LINE!>>%PARENT%\libidn.mak
)
ECHO.
ECHO GNU IDN Library for Windows configuration complete!
GOTO DONE

:GET_ARGS
ECHO.%~2 | FINDSTR /C:"%~1" 1>nul
IF NOT errorlevel 1 (
	SET KEY=%~2
) ELSE (
	SET VALUE=%~2
)
IF DEFINED KEY (
	SET %KEY%=%~2
)
IF DEFINED VALUE (
	IF DEFINED KEY (
		SET %KEY%=%~2
	)
	SET KEY=
	SET VALUE=
)
GOTO:EOF

:USAGE
ECHO.
ECHO * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
ECHO Usage: %ME% [options]
ECHO * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
ECHO --prefix: install base directory. Default value: 3rdparty\idn.  Two directories
ECHO    are created under this one: include, to use with /I compiler option and lib, 
ECHO    to use with /LIBPATH linker option.
ECHO --source: GNU Libidn source code directory. Default value:
ECHO    %USERPROFILE%\dev\libidn.
ECHO --cvars: compiler variables definitions by -D.
ECHO --cdebug: compiler debug options.
ECHO --cflags: other compiler flags.
ECHO --lflags: linker flags.
ECHO --implibs: import libraries.
ECHO.
ECHO Note that CL and LIB options above are added to those defined in win32.mak.
ECHO.
:DONE
ENDLOCAL
