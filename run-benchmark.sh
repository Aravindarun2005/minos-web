#!/usr/bin/env bash
# Performance evaluation like Section VII of the paper (Figures 2-5).
# Full run (1..100 attributes/keywords, 10 runs per point): about 10-20 minutes.
# Faster trial: ./run-benchmark.sh --quick
cd "$(dirname "$0")"
[ -d minos-java/test-build ] || ./build.sh
java -cp "minos-java/build:minos-java/lib/*:minos-java/test-build" Benchmark "$@"
