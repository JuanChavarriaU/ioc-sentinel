#!/usr/bin/env bash
# IoC Sentinel - Vultr Cloud Compute VM bootstrap (Ubuntu 24.04 LTS).
# Run as root on a fresh VM from the repo root:
#   sudo ./infra/vm/bootstrap.sh            # Docker + jail + firewall + images
#   sudo WITH_GVISOR=1 ./infra/vm/bootstrap.sh
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WITH_GVISOR="${WITH_GVISOR:-0}"
APP_USER="${APP_USER:-${SUDO_USER:-root}}"

step() { echo -e "\n\033[1;36m==> $*\033[0m"; }
[[ $EUID -eq 0 ]] || { echo "run as root (sudo)"; exit 1; }
. /etc/os-release
[[ "${VERSION_ID}" == "24.04" ]] || echo "WARNING: tested on Ubuntu 24.04, found ${PRETTY_NAME}"

step "Base packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ca-certificates curl gnupg git make jq ufw python3-venv python3-pip iptables

step "Docker Engine (official repo)"
if ! command -v docker >/dev/null; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
# Hardened daemon defaults: no inter-container traffic on default bridge, live restore, log caps.
if [[ ! -f /etc/docker/daemon.json ]]; then
  cat >/etc/docker/daemon.json <<'JSON'
{
  "icc": false,
  "live-restore": true,
  "no-new-privileges": true,
  "log-driver": "json-file",
  "log-opts": { "max-size": "20m", "max-file": "3" }
}
JSON
fi
systemctl enable --now docker
systemctl restart docker
[[ "$APP_USER" != "root" ]] && usermod -aG docker "$APP_USER" || true

if [[ "$WITH_GVISOR" == "1" ]]; then
  step "gVisor (runsc)"
  bash "$REPO_DIR/infra/vm/gvisor.sh"
fi

step "Host firewall (ufw): SSH + HTTP(S) only"
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
if [[ -n "${VPC_CIDR:-}" ]]; then
  ufw allow from "$VPC_CIDR" comment "ioc-sentinel VPC"   # control plane <-> future workers
fi
ufw --force enable

step "Jail network for sandboxes"
bash "$REPO_DIR/infra/vm/jail-network.sh" up
install -m 0644 "$REPO_DIR/infra/systemd/ioc-jail.service" /etc/systemd/system/ioc-jail.service
sed -i "s|@REPO_DIR@|$REPO_DIR|g" /etc/systemd/system/ioc-jail.service
systemctl daemon-reload
systemctl enable ioc-jail.service

step "Sandbox image"
docker build -t ioc-sentinel/sandbox-browser:latest "$REPO_DIR/sandbox/browser"

step "API virtualenv"
sudo -u "$APP_USER" bash -c "cd '$REPO_DIR' && python3 -m venv .venv && .venv/bin/pip install -q -r apps/api/requirements.txt"
[[ -f "$REPO_DIR/.env" ]] || sudo -u "$APP_USER" cp "$REPO_DIR/.env.example" "$REPO_DIR/.env"
chmod 600 "$REPO_DIR/.env"
if [[ "$WITH_GVISOR" == "1" ]] && command -v runsc >/dev/null; then
  sed -i 's/^SANDBOX_RUNTIME=.*/SANDBOX_RUNTIME=runsc/' "$REPO_DIR/.env"
fi

step "Done"
cat <<EOF
Next:
  1. Put your key in $REPO_DIR/.env  (VULTR_INFERENCE_API_KEY=...)
  2. make check-models
  3. make smoke          # sandbox vs example.com + containment probes
  4. make api            # FastAPI on :8000 (put Caddy/nginx in front for 443)
EOF
