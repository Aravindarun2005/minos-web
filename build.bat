@echo off
rem Builds minos-java, then backend, then tests. JDK 17+.
rem Uses relative paths only, so it works when the folder path contains spaces.
cd /d "%~dp0"
for %%d in (minos-java\build minos-java\test-build backend\build backend\test-build) do if exist "%%d" rmdir /s /q "%%d"
mkdir minos-java\build minos-java\test-build backend\build backend\test-build

javac -encoding UTF-8 -cp "minos-java/lib/*" -d minos-java\build minos-java\src\minos\common\*.java minos-java\src\minos\core\*.java minos-java\src\minos\ext\*.java || goto :fail
javac -encoding UTF-8 -cp "minos-java/build;minos-java/lib/*" -d backend\build backend\src\minos\server\*.java backend\src\minos\csp\*.java || goto :fail
javac -encoding UTF-8 -cp "minos-java/build;minos-java/lib/*" -d minos-java\test-build minos-java\test\*.java || goto :fail
javac -encoding UTF-8 -cp "backend/build;minos-java/build;minos-java/lib/*" -d backend\test-build backend\test\*.java || goto :fail
echo Build OK
exit /b 0
:fail
echo Build FAILED
exit /b 1
