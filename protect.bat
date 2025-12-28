@echo off
echo 🛡️ BLACS Tamper-Proof Guardian
echo ===============================

REM Check for admin privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    echo ✅ Administrator privileges: VERIFIED
) else (
    echo 🚫 Administrator privileges required!
    echo    Right-click and select "Run as administrator"
    pause
    exit /b 1
)

if "%~1"=="" (
    echo Usage: protect.bat "application_path" [protection_level]
    echo.
    echo Examples:
    echo   protect.bat "C:\Windows\System32\calc.exe" high
    echo   protect.bat "C:\Program Files\MyGame\game.exe" maximum
    echo   protect.bat calc.exe medium
    echo.
    echo Protection levels: low, medium, high, maximum
    echo Default level: high
    pause
    exit /b 1
)

set APP_PATH=%~1
set PROTECTION_LEVEL=%~2

if "%PROTECTION_LEVEL%"=="" (
    set PROTECTION_LEVEL=high
)

echo 🎯 Target Application: %APP_PATH%
echo 🔒 Protection Level: %PROTECTION_LEVEL%
echo 🛡️ Tamper-Proof: ENABLED
echo 🔍 DSLL Technology: ACTIVE
echo.

echo 🚀 Starting BLACS Tamper-Proof Guardian...
python blacs_guardian.py "%APP_PATH%" --level %PROTECTION_LEVEL%

echo.
echo ✅ BLACS Guardian session completed
pause