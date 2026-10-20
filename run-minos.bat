@echo off
cd /d "%~dp0"
if not exist backend\build\minos call build.bat
java -cp "backend/build;minos-java/build;minos-java/lib/*" minos.server.MinosServer --port=8080 --csp=http://localhost:9090 --data=backend/minos-data --web=frontend %*
