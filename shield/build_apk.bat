@echo off
rem Builds the FraudLens app APK (FraudLens + Shield in one) without opening Android Studio (Android Studio must be installed once).
cd /d "%~dp0"
if not defined JAVA_HOME if exist "C:\Program Files\Android\Android Studio\jbr" set "JAVA_HOME=C:\Program Files\Android\Android Studio\jbr"
if not exist local.properties (
  set "SDK=%LOCALAPPDATA%\Android\Sdk"
  call echo sdk.dir=%%SDK:\=\\%%> local.properties
)
call gradlew.bat assembleDebug
if errorlevel 1 (echo. & echo BUILD FAILED - open this folder in Android Studio instead. & pause & exit /b 1)
copy /y app\build\outputs\apk\debug\app-debug.apk FraudLens.apk >nul
echo.
echo Done: %CD%\FraudLens.apk
pause
