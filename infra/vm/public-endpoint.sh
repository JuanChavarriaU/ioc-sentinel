#!/usr/bin/env bash
# Expose the dashboard/API publicly with automatic HTTPS (Caddy + Let's Encrypt) and run the API as a service.
# Usage: sudo ./public-endpoint.sh [domain]
#   domain defaults to <public-ip-with-dashes>.sslip.io (no DNS needed).
set -euo pipefail

REPO_DIR="${REPO_DIR:-/opt/ioc-sentinel}"
APP_USER="${APP_USER:-${SUDO_USER:-alexander}}"
PUBLIC_IP="$(curl -4 -s https://ifconfig.me)"
DOMAIN="${1:-${PUBLIC_IP//./-}.sslip.io}"

echo "==> Caddy"
if ! command -v caddy >/dev/null; then
  apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https curl gpg
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -qq && apt-get install -y -qq caddy
fi
cat >/etc/caddy/Caddyfile <<EOF
${DOMAIN} {
	encode zstd gzip
	header {
		X-Content-Type-Options nosniff
		Referrer-Policy no-referrer
		-Server
	}
	reverse_proxy 127.0.0.1:8000 {
		transport http {
			response_header_timeout 180s
		}
	}
}
EOF
systemctl enable --now caddy
systemctl reload caddy

echo "==> API service"
sed -e "s|__APP_USER__|${APP_USER}|g" -e "s|__REPO_DIR__|${REPO_DIR}|g" \
  "${REPO_DIR}/infra/systemd/ioc-api.service" >/etc/systemd/system/ioc-api.service
mkdir -p "${REPO_DIR}/data" && chown -R "${APP_USER}" "${REPO_DIR}/data"
systemctl daemon-reload
systemctl enable ioc-api
systemctl restart ioc-api

echo "==> Done: https://${DOMAIN}/"
