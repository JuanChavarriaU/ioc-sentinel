#!/usr/bin/env bash
# Day-1 smoke test on the VM: jail up, sandbox runs, containment probes blocked.
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; [[ -f .env ]] && . ./.env; set +a
PY="$PWD/.venv/bin/python"; [[ -x $PY ]] || PY=python3
TARGET="${1:-https://example.com}"

echo "== jail rules"; sudo bash infra/vm/jail-network.sh status | grep -cE "REJECT" | xargs echo "REJECT rules:"
echo "== sandbox run -> $TARGET"
cd apps/api && $PY -m app.sandbox.runner "$TARGET"
cd ../..
LAST=$(ls -td data/scans/*/ | head -1)
echo "== containment probes (all must be blocked)"
$PY - "$LAST/result.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
probes = r["observations"].get("containment", [])
bad = [p for p in probes if p["status"] == "REACHABLE"]
for p in probes: print(f"  {p['target']:<20} {p['addr']:<22} {p['status']}")
print("  docker ps leftovers: check `docker ps -a --filter label=app=ioc-sentinel`")
sys.exit(1 if bad else 0)
PY
echo "PASS: artifacts in $LAST"
