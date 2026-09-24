@echo off
setlocal EnableExtensions
rem Runs the server's automatic tests (85 tests: engine, ML, threat intel, security, free APIs).
rem Needs RUN_SERVER_ON_THIS_PC.bat to have been run once (it installs the packages).
title FraudLens server tests
set "HERE=%~dp0"
set "PYEXE=%HERE%.venv\Scripts\python.exe"
if exist "%PYEXE%" goto run
echo.
echo  Run RUN_SERVER_ON_THIS_PC.bat once first: it installs the packages the tests need.
pause
exit /b 1

:run
set "PYTHONDONTWRITEBYTECODE=1"
pushd "%HERE%..\1-server"
"%PYEXE%" -B -m pytest -q -p no:cacheprovider tests
set "RESULT=%errorlevel%"
popd
echo.
if "%RESULT%"=="0" echo  All tests passed.
if not "%RESULT%"=="0" echo  Some tests failed: copy the text above and send it to Claude.
pause
