#!/usr/bin/env bash
# 1) offline check of the ten algorithms and the paper's printed equations (minos-java)
# 2) HTTP end-to-end test on fresh servers (ports 18080/19090), including a restart of both servers
set -e
cd "$(dirname "$0")"
./build.sh
CP="backend/build:minos-java/build:minos-java/lib/*"
java -cp "minos-java/build:minos-java/lib/*:minos-java/test-build" PaperEquationCheck
T=$(mktemp -d)
start() {
  java -cp "$CP" minos.csp.CspServer --port=19090 --storage="$T/csp-storage" > "$T/csp.log" 2>&1 & CSP=$!
  java -cp "$CP" minos.server.MinosServer --port=18080 --csp=http://localhost:19090 --data="$T/minos-data" --web=frontend > "$T/minos.log" 2>&1 & MIN=$!
  sleep 3
}
stop() { kill $CSP $MIN 2>/dev/null || true; wait $CSP $MIN 2>/dev/null || true; }
trap stop EXIT
start
java -cp "$CP:backend/test-build" EndToEndTest phase1 http://localhost:18080
echo; echo "== restarting both servers =="; stop; start
java -cp "$CP:backend/test-build" EndToEndTest phase2 http://localhost:18080
echo "Test data left in $T"
