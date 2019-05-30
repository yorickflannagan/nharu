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
SET VERSION=%VER%%
SET CVERSION=%VERSION:.=_%
ECHO const char *NHARU_VERSION_%CVERSION% = "%VERSION%";>%CUR%native\version.c
ECHO const char *NHARU_getVersion() { return NHARU_VERSION_%CVERSION%; }>>%CUR%native\version.c


ENDLOCAL