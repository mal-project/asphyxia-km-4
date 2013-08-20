@ECHO OFF
REM --------------------------------------------------------------------
REM link.cmd v 0.3.0

REM --------------------------------------------------------------------
SET FILENAME=main
SET MASM=\programs\development\rce\assemblers\masm
SET LIB=%masm%\lib

SET USE_PELLES=1
SET LINK_ARGS=/nologo /release /subsystem:windows /libpath:%lib% /out:"bin\%filename%.exe" %filename%.obj
REM --------------------------------------------------------------------

IF %USE_PELLES%==1 (
    REM polink uses res, instead of obj... witch is *better*
    %MASM%\bin\polink %LINK_ARGS% "res\rsrc.res"
) ELSE (
    %MASM%\bin\link %LINK_ARGS% "res\rsrc.obj"
)

ECHO done.
PAUSE>NUL
EXIT
REM --------------------------------------------------------------------