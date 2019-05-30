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
ECHO const char *NHARU_VERSION = "%VERSION%";>%CUR%native\version.c
ECHO const char *NHARU_getVersion() { return NHARU_VERSION; }>>%CUR%native\version.c


ENDLOCAL