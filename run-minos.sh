#!/usr/bin/env bash
# Minos Server + web app: http://localhost:8080 (serves frontend/, talks to the CSP at :9090)
# Optional: export MINOS_VAULT_PASSPHRASE=... to derive the key-vault key from a passphrase.
cd "$(dirname "$0")"
[ -d backend/build/minos ] || ./build.sh
exec java -cp "backend/build:minos-java/build:minos-java/lib/*" minos.server.MinosServer --port=8080 --csp=http://localhost:9090 --data=backend/minos-data --web=frontend "$@"
