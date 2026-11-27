@echo off
setlocal
cd /d "%~dp0"
title SENTINEL Desktop Launcher
if not exist "sentinel\gui.py" goto missing
if not exist "rules\hashes.json" goto missing
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)" >nul 2>&1
if not errorlevel 1 goto pylauncher
python -c "import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)" >nul 2>&1
if not errorlevel 1 goto pythonlauncher
echo Python 3.11 or newer was not found. Install standard Python for Windows with Tcl/Tk and the launcher enabled.
echo https://www.python.org/downloads/windows/
goto failed
:pylauncher
py -3 -c "import tkinter; import sentinel.cli" 
if errorlevel 1 goto failed
py -3 -m sentinel gui
if errorlevel 1 goto failed
exit /b 0
:pythonlauncher
python -c "import tkinter; import sentinel.cli"
if errorlevel 1 goto failed
python -m sentinel gui
if errorlevel 1 goto failed
exit /b 0
:missing
echo Extract ALL files from the SENTINEL Desktop ZIP before opening GUI.cmd.
:failed
echo.
echo SENTINEL could not start. Copy the error above. If tkinter is missing, modify your Python installation and enable Tcl/Tk and IDLE.
pause
exit /b 1
