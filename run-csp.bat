@echo off
cd /d "%~dp0"
if not exist backend\build\minos call build.bat
java -cp "backend/build;minos-java/build;minos-java/lib/*" minos.csp.CspServer --port=9090 --storage=backend/csp-storage %*
