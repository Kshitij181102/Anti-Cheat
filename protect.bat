@echo off
REM BLACS Protection Script
REM Usage: protect.bat "path\to\executable.exe" [protection_level]

if "%1"=="" (
    echo Usage: protect.bat "path\to\executable.exe" [protection_level]
    echo.
    echo Protection Levels:
    echo   low      - Basic protection, DSLL disabled
    echo   medium   - Balanced detection, DSLL enabled
    echo   high     - Strict detection, Full DSLL monitoring ^(default^)
    echo   maximum  - Extreme sensitivity, Advanced DSLL analysis
    echo.
    echo Examples:
    echo   protect.bat "C:\Windows\System32\notepad.exe"
    echo   protect.bat "C:\Windows\System32\calc.exe" high
    echo   protect.bat "C:\Program Files\MyGame\game.exe" maximum
    exit /b 1
)

set EXECUTABLE=%1
set LEVEL=%2

if "%LEVEL%"=="" set LEVEL=high

echo Starting BLACS protection...
python -m blacs.cli protect %EXECUTABLE% --level %LEVEL%