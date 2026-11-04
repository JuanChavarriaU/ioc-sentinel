#!/usr/bin/env bash
# Install gVisor (runsc) and register it as a Docker runtime.
# After this, set SANDBOX_RUNTIME=runsc in .env.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }

curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor --yes -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
  > /etc/apt/sources.list.d/gvisor.list
apt-get update -y
apt-get install -y runsc
runsc install          # adds "runsc" to /etc/docker/daemon.json
systemctl restart docker

echo "Verifying runsc..."
docker run --rm --runtime=runsc hello-world >/dev/null && echo "gVisor OK"
docker run --rm --runtime=runsc busybox dmesg 2>/dev/null | head -3 || true
