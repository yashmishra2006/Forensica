@echo off
setlocal enabledelayedexpansion
color 0A
mode con: cols=90 lines=30

:menu
cls
echo.
echo ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗ ██████╗ █████╗ 
echo ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██╔════╝██╔══██╗
echo ███████╗██║   ██║██████╔╝█████╗  ██╔██╗ ██║█████╗  ██║     ███████║
echo ╚════██║██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║██╔══╝  ██║     ██╔══██║
echo ███████║╚██████╔╝██║     ███████╗██║ ╚████║███████╗╚██████╗██║  ██║
echo ╚══════╝ ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝
echo ------------------------------------------------------------------
echo            Forensica Toolkit — Digital File Analyzer
echo ------------------------------------------------------------------
echo [1] Run Analysis
echo [2] Change Directory
echo [3] Exit
echo ------------------------------------------------------------------
set /p choice="Choose an option: "

if "%choice%"=="1" goto analyze
if "%choice%"=="2" goto changedir
if "%choice%"=="3" exit
goto menu

:analyze
cls
echo [*] Initializing scanner...🔍
python analyze.py

if exist "output.json" (
    echo.
    echo [✓] Analysis complete. Output saved to ^"output.json^"
    echo [*] Displaying output in pretty format...📜
    echo ---------------------------------------------------------------
    python pretty_print_json.py "output.json"
    echo ---------------------------------------------------------------
) else (
    echo [!] Error: output.json not found. Check analyze.py script.
)
pause
goto menu

:changedir
cls
set /p newdir="Enter full path to directory you want to analyze: "
cd /d "%newdir%"
echo [✓] Switched to directory: %CD%
pause
goto menu
