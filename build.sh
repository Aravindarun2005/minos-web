#!/usr/bin/env bash
# Builds minos-java (Minos algorithms + extensions), then backend (Minos + CSP servers), then tests. JDK 17+.
set -e
cd "$(dirname "$0")"
rm -rf minos-java/build minos-java/test-build backend/build backend/test-build
mkdir -p minos-java/build minos-java/test-build backend/build backend/test-build
javac -encoding UTF-8 -cp "minos-java/lib/*" -d minos-java/build $(find minos-java/src -name "*.java")
javac -encoding UTF-8 -cp "minos-java/build:minos-java/lib/*" -d backend/build $(find backend/src -name "*.java")
javac -encoding UTF-8 -cp "minos-java/build:minos-java/lib/*" -d minos-java/test-build minos-java/test/*.java
javac -encoding UTF-8 -cp "backend/build:minos-java/build:minos-java/lib/*" -d backend/test-build backend/test/*.java
echo "Build OK"
