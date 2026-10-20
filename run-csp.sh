#!/usr/bin/env bash
# CSP Server: http://localhost:9090, storage backend/csp-storage
cd "$(dirname "$0")"
[ -d backend/build/minos ] || ./build.sh
exec java -cp "backend/build:minos-java/build:minos-java/lib/*" minos.csp.CspServer --port=9090 --storage=backend/csp-storage "$@"
