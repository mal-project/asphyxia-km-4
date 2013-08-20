@ECHO OFF
REM --------------------------------------------------------------------
REM project.cmd version 1.0.3

REM --------------------------------------------------------------------
SET PROJECT=%CD%
SET TEMPLATE=\Documents\Projects\Development\Assembler\RCE\Res\Templates\general.template.v1.9
SET LOG=%PROJECT%\bak\project.log
REM --------------------------------------------------------------------

REM --------------------------------------------------------------------
IF EXIST "%PROJECT%\bak" (
    ECHO Already done.
    EXIT
)

MD "%PROJECT%\bak"
ECHO ; %DATE% > "%LOG%"
REM --------------------------------------------------------------------

ECHO.
SET /P CHOISE=Create an empty project on current directory? y/n

REM --------------------------------------------------------------------
IF %CHOISE%==y (
    xcopy "%TEMPLATE%" "%PROJECT%" /T /E /Y >> "%LOG%"
    xcopy "%TEMPLATE%" "%PROJECT%" /S /Y /EXCLUDE:%TEMPLATE%\project.cmd >> "%LOG%"
    
) ELSE (
    ECHO Cancelled.
    PAUSE>NUL
)
EXIT
REM --------------------------------------------------------------------