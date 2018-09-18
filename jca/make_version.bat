@ECHO OFF
SETLOCAL EnableExtensions
SETLOCAL EnableDelayedExpansion
:: CREATES A VERSION FILE FOR SHARED LIBRARY
:: %~1: VERSION NUMBER
:: %~2: DIRECTORY WHERE TO CREATE C FILE
:: REQUIRES AN ANT build.number FILE IN CURRENT DIRECTORY
:: BUILD INCREMENT IS IMPLEMENTED BY ANT DUE TO ENSURE EQUALITY TO JAVA

SET ME=%~n0
SET CUR=%~dp0
SET VER=%~1
SET OUTPUT=%~2
IF "%VER%" EQU "" (
	ECHO %ME%: Version number required
	EXIT /B 1
)
IF NOT EXIST %CUR%build.number (
	ECHO %ME%: File %CUR%build.number cannot be read
	EXIT /B 1
)
FOR /F "tokens=1,2 delims==" %%a IN (%CUR%build.number) DO SET BUILD=%%b
SET VERSION=%VER%.%BUILD%
SET CVERSION=%VERSION:.=_%
ECHO const char *NHARU_VERSION_%CVERSION% = "%VERSION%";>%OUTPUT%\version.c
ECHO const char *NHARU_getVersion() { return NHARU_VERSION_%CVERSION%; }>>%OUTPUT%\version.c

ENDLOCAL