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
obs = r["observations"]
probes = obs.get("containment", [])
bad = [p for p in probes if p["status"] == "REACHABLE"]
for p in probes: print(f"  {p['target']:<20} {p['addr']:<22} {p['status']}")
# The sandbox must also be USEFUL: the page has to load (catches e.g. broken DNS under gVisor).
nav = [e for e in obs.get("errors", []) if e.get("stage") == "navigate"]
if nav or not (obs.get("final_url") or "").startswith("http"):
    print(f"  FAIL: sandbox could not load the page: {nav or obs.get('final_url')}")
    sys.exit(1)
print("  docker ps leftovers: check `docker ps -a --filter label=app=ioc-sentinel`")
sys.exit(1 if bad else 0)
PY
echo "PASS: artifacts in $LAST"
