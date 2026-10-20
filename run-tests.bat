@echo off
rem Offline algorithm check. For the HTTP end-to-end test start both servers, then:
rem   java -cp "backend/build;minos-java/build;minos-java/lib/*;backend/test-build" EndToEndTest phase1 http://localhost:8080
rem   (restart both servers)
rem   java -cp "backend/build;minos-java/build;minos-java/lib/*;backend/test-build" EndToEndTest phase2 http://localhost:8080
cd /d "%~dp0"
call build.bat || exit /b 1
java -cp "minos-java/build;minos-java/lib/*;minos-java/test-build" PaperEquationCheck
