@echo off
setlocal EnableExtensions
rem =====================================================================================
rem  PLAN B: run the FraudLens server on THIS computer instead of the free cloud server.
rem  Use it if Render is down or the venue has no internet during the presentation.
rem  In the extension, connect to:   127.0.0.1:8000
rem  Nothing is written inside 1-server: packages, models and data stay in this folder.
rem =====================================================================================
title FraudLens server (this computer)

rem A click inside a Command Prompt window ("Select" mode) freezes the program running in it.
rem Switch that off for this window so a stray click can't pause the server during a demo.
powershell -NoProfile -Command "$s='[DllImport(\"kernel32.dll\")]public static extern IntPtr GetStdHandle(int h);[DllImport(\"kernel32.dll\")]public static extern bool GetConsoleMode(IntPtr h,out int m);[DllImport(\"kernel32.dll\")]public static extern bool SetConsoleMode(IntPtr h,int m);';$t=Add-Type -MemberDefinition $s -Name QE -Namespace FL -PassThru;$h=$t::GetStdHandle(-10);$m=0;[void]$t::GetConsoleMode($h,[ref]$m);[void]$t::SetConsoleMode($h,(($m -band (-bnot 0x40)) -bor 0x80))" >nul 2>&1

set "HERE=%~dp0"
set "SERVER=%HERE%..\1-server"
set "KEYS=%HERE%..\MY_KEYS.txt"
set "VENV=%HERE%.venv"
set "PYEXE=%HERE%.venv\Scripts\python.exe"
set "DATA=%HERE%local-data"
set "MODELS=%HERE%local-models"
rem If the old fraudlens folder is next to EXTENSION V2, its downloaded AI model is reused.
set "OLDMODEL=%HERE%..\..\fraudlens\backend\models\multilingual-e5-small\onnx\model_quantized.onnx"
if not exist "%OLDMODEL%" set "OLDMODEL=%HERE%..\..\backend\models\multilingual-e5-small\onnx\model_quantized.onnx"
set "PYTHONIOENCODING=utf-8"

if not exist "%SERVER%\app\main.py" goto no_server
if exist "%KEYS%" goto keys_ok
if exist "%KEYS%.txt" copy /Y "%KEYS%.txt" "%KEYS%" >nul
if exist "%KEYS%" goto keys_ok
echo.
echo  Note: MY_KEYS.txt was not found in the EXTENSION V2 folder, so the server runs without API keys.
echo  It still works: rules, AI models, OpenPhish and the offline phone check need no keys.
echo.
:keys_ok

rem ---- 1. A private Python environment (first run only) --------------------------------
if exist "%PYEXE%" goto have_venv
set "BASE="
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1 && set "BASE=py -3"
if defined BASE goto make_venv
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1 && set "BASE=python"
if defined BASE goto make_venv
goto no_python

:make_venv
echo.
echo  First run: creating a private Python environment in 3-backup-and-tests\.venv
echo.
%BASE% -m venv "%VENV%"
if errorlevel 1 goto venv_failed

:have_venv
"%PYEXE%" -c "import fastapi, uvicorn, onnxruntime, sentencepiece, phonenumbers" >nul 2>&1
if not errorlevel 1 goto have_packages
echo.
echo  Installing the server's packages. First run only: 3 to 5 minutes, needs internet...
echo.
"%PYEXE%" -m pip install --upgrade pip --quiet
"%PYEXE%" -m pip install -r "%SERVER%\requirements.txt"
if errorlevel 1 goto pip_failed

:have_packages
rem ---- 2. Models and data live in this folder, never inside 1-server ----------------------
if not exist "%MODELS%\artifacts" xcopy "%SERVER%\models" "%MODELS%" /E /I /Q /Y >nul
if not exist "%DATA%\seed" xcopy "%SERVER%\data\seed" "%DATA%\seed" /E /I /Q /Y >nul
if exist "%MODELS%\multilingual-e5-small\onnx\model_quantized.onnx" goto have_model
if not exist "%OLDMODEL%" goto download_model
echo  Copying the AI model from your old fraudlens folder...
if not exist "%MODELS%\multilingual-e5-small\onnx" mkdir "%MODELS%\multilingual-e5-small\onnx"
copy /Y "%OLDMODEL%" "%MODELS%\multilingual-e5-small\onnx\model_quantized.onnx" >nul
if exist "%MODELS%\multilingual-e5-small\onnx\model_quantized.onnx" goto have_model

:download_model
echo  Downloading the AI model: 118 MB, first run only...
set "FRAUDLENS_MODELS_DIR=%MODELS%"
pushd "%SERVER%"
"%PYEXE%" -B -m scripts.download_models
popd
if exist "%MODELS%\multilingual-e5-small\onnx\model_quantized.onnx" goto have_model
echo.
echo  The AI model could not be downloaded (no internet?). The server still starts, with a lighter
echo  model. Run this file again with internet to get the full model.
echo.

:have_model
rem ---- 3. Settings: your keys file + safe defaults ----------------------------------------
set "FRAUDLENS_DATA_DIR=%DATA%"
set "FRAUDLENS_MODELS_DIR=%MODELS%"
set "FRAUDLENS_ENV_FILE=%KEYS%"
set "FRAUDLENS_REQUIRE_INSTALL_TOKEN=true"
set "PYTHONDONTWRITEBYTECODE=1"

netstat -ano | findstr /R /C:"127.0.0.1:8000 .*LISTENING" /C:"0.0.0.0:8000 .*LISTENING" >nul 2>&1
if not errorlevel 1 goto port_busy

echo.
echo  =====================================================================
echo   FraudLens server is starting on this computer.
echo   When you see "Application startup complete":
echo     - in the FraudLens panel, connect to:   127.0.0.1:8000
echo     - practice pages:  http://127.0.0.1:8000/demo/
echo   Keep this window open. Press Ctrl+C to stop the server.
echo  =====================================================================
echo.
pushd "%SERVER%"
"%PYEXE%" -B -m uvicorn app.main:app --host 127.0.0.1 --port 8000
popd
echo.
echo  The server stopped. If there is an error above, copy it and send it to Claude.
pause
exit /b 0

:no_server
echo.
echo  Can't find the 1-server folder next to this folder.
echo  Keep the EXTENSION V2 folder together: 1-server, 2-chrome-extension, 3-backup-and-tests.
pause
exit /b 1

:no_python
echo.
echo  Python 3.11 or newer is not installed on this computer.
echo  Install Python 3.12 from https://www.python.org/downloads/
echo  and tick "Add python.exe to PATH" in the installer. Then run this file again.
pause
exit /b 1

:venv_failed
echo.
echo  Could not create the Python environment. Delete the folder 3-backup-and-tests\.venv and try again.
pause
exit /b 1

:pip_failed
echo.
echo  Installing packages failed. Check the internet connection, delete the folder
echo  3-backup-and-tests\.venv and run this file again.
pause
exit /b 1

:port_busy
echo.
echo  Something is already using port 8000 on this computer, maybe another FraudLens window
echo  or the old run_backend.bat. Close it, then run this file again.
pause
exit /b 1
