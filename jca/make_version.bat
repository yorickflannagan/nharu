@ECHO OFF
SETLOCAL EnableDelayedExpansion
:: CREATES A VERSION FILE FOR SHARED LIBRARY
:: %~1: VERSION NUMBER
:: REQUIRES AN ANT build.number FILE IN CURRENT DIRECTORY

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
ECHO const char *NHARU_VERSION_%CVERSION% = "%VERSION%";>%CUR%native\version.c
ECHO const char *NHARU_getVersion() { return NHARU_VERSION_%CVERSION%; }>>%CUR%native\version.c
SET /A BUILD=%BUILD%+1
ECHO #Build number for Nharu JCA. Do not edit>%CUR%build.number
FOR /F "tokens=* USEBACKQ" %%F IN (`powershell -Command "Get-Date -format u"`) DO (
	SET DAT=%%F
)
ECHO #%DAT%>>%CUR%build.number
ECHO build.number=%BUILD%>>%CUR%build.number

ENDLOCAL