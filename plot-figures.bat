@echo off
rem Draws Figures 2-5 like the paper from benchmark-results\*.csv (needs Python 3).
cd /d "%~dp0"
where python >nul 2>nul || (echo Python is not installed. Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH". & pause & exit /b 1)
python -c "import matplotlib" 2>nul || python -m pip install matplotlib
python plot_figures.py %*
if not errorlevel 1 start "" benchmark-results
pause
