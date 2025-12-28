@echo off
echo 🛡️ BLACS Universal Application Protector
echo ========================================

if "%~1"=="" (
    echo Usage: protect.bat "application_path" [protection_level]
    echo.
    echo Examples:
    echo   protect.bat "C:\Windows\System32\calc.exe" high
    echo   protect.bat "C:\Windows\System32\notepad.exe" maximum
    echo   protect.bat "C:\Program Files\MyGame\game.exe" high
    echo   protect.bat calc.exe medium
    echo.
    echo Protection levels: low, medium, high, maximum
    echo Default level: high
    exit /b 1
)

set APP_PATH=%~1
set PROTECTION_LEVEL=%~2

if "%PROTECTION_LEVEL%"=="" (
    set PROTECTION_LEVEL=high
)

echo 🎯 Target Application: %APP_PATH%
echo 🔒 Protection Level: %PROTECTION_LEVEL%
echo 🔍 DSLL Technology: ENABLED
echo.

echo 🚀 Starting BLACS protection with DSLL (Monitor Mode)...
python protect_app.py "%APP_PATH%" --level %PROTECTION_LEVEL%

echo.
echo ✅ BLACS protection session completed
pause