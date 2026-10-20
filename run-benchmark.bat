@echo off
rem Performance evaluation like Section VII of the paper (Figures 2-5).
rem Full run: about 10-20 minutes.  Faster trial: run-benchmark.bat --quick
cd /d "%~dp0"
if not exist minos-java\test-build call build.bat
java -cp "minos-java/build;minos-java/lib/*;minos-java/test-build" Benchmark %*
echo.
echo Open benchmark-results\report.html to see the graphs.
pause
