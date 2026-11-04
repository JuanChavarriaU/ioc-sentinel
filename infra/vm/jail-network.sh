#!/usr/bin/env bash
# IoC Sentinel - "jail" network for sandboxes.
#
# Containers on this bridge may ONLY talk to the public Internet on web ports,
# resolve DNS through the configured public resolvers, and nothing else:
#   - cloud metadata (169.254.0.0/16)            -> REJECT + LOG
#   - RFC1918 / CGNAT / loopback / multicast      -> REJECT + LOG
#   - the VM itself (INPUT from the bridge)       -> REJECT + LOG
#   - container <-> container (icc=false)         -> blocked by Docker
#   - non-web ports (SMTP, SSH, IRC, ...)         -> REJECT + LOG
#
# Idempotent: safe to re-run (boot, deploy, demo reset).
# Usage: sudo ./jail-network.sh [up|down|status]
#   LAB_ALLOW="172.30.0.1:8088"  optional host:port exceptions for local trap testing ONLY.
set -euo pipefail

NET="${SANDBOX_NETWORK:-ioc-jail}"
BR="${JAIL_BRIDGE:-br-ioc-jail}"
SUBNET="${JAIL_SUBNET:-172.30.0.0/24}"
RESOLVERS="${SANDBOX_DNS:-1.1.1.1,9.9.9.9}"
WEB_PORTS="${JAIL_TCP_PORTS:-80,443,8080,8443}"
LAB_ALLOW="${LAB_ALLOW:-}"
CHAIN="IOC-JAIL"
BLOCKED_CIDRS=(
  169.254.0.0/16   # link-local: cloud instance metadata (Vultr/AWS/GCP 169.254.169.254)
  10.0.0.0/8       # RFC1918 (Vultr VPC lives here)
  172.16.0.0/12    # RFC1918 (Docker default bridges)
  192.168.0.0/16   # RFC1918
  100.64.0.0/10    # CGNAT
  127.0.0.0/8      # loopback
  0.0.0.0/8
  224.0.0.0/4      # multicast
  240.0.0.0/4      # reserved
)

log() { echo "[jail] $*"; }

ensure_network() {
  if ! docker network inspect "$NET" >/dev/null 2>&1; then
    log "creating docker network $NET ($SUBNET, bridge $BR, icc=false)"
    docker network create \
      --driver bridge \
      --subnet "$SUBNET" \
      --opt "com.docker.network.bridge.name=$BR" \
      --opt "com.docker.network.bridge.enable_icc=false" \
      --label app=ioc-sentinel \
      "$NET" >/dev/null
  else
    log "network $NET already exists"
  fi
}

reset_chain() {
  iptables -N "$CHAIN" 2>/dev/null || true
  iptables -F "$CHAIN"
}

rule_lab_allow() {
  [[ -z "$LAB_ALLOW" ]] && return 0
  IFS=',' read -ra items <<<"$LAB_ALLOW"
  for item in "${items[@]}"; do
    local host="${item%%:*}" port="${item##*:}"
    log "LAB exception: $host:$port (do NOT use in production)"
    iptables -A "$CHAIN" -p tcp -d "$host" --dport "$port" -j RETURN
    iptables -I INPUT 1 -i "$BR" -p tcp -d "$host" --dport "$port" -j ACCEPT
  done
}

build_rules() {
  # Replies to connections the container opened.
  iptables -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  rule_lab_allow
  # Private / metadata destinations.
  for cidr in "${BLOCKED_CIDRS[@]}"; do
    iptables -A "$CHAIN" -d "$cidr" -m limit --limit 20/min -j LOG --log-prefix "IOC-JAIL-BLOCK " --log-level 4
    iptables -A "$CHAIN" -d "$cidr" -j REJECT --reject-with icmp-admin-prohibited
  done
  # DNS only to the configured public resolvers.
  IFS=',' read -ra rs <<<"$RESOLVERS"
  for r in "${rs[@]}"; do
    iptables -A "$CHAIN" -p udp -d "$r" --dport 53 -j RETURN
    iptables -A "$CHAIN" -p tcp -d "$r" --dport 53 -j RETURN
  done
  # Web ports only (QUIC/UDP 443 is rejected so Chromium falls back to TCP, which we can see).
  iptables -A "$CHAIN" -p tcp -m multiport --dports "$WEB_PORTS" -j RETURN
  iptables -A "$CHAIN" -m limit --limit 20/min -j LOG --log-prefix "IOC-JAIL-PORT " --log-level 4
  iptables -A "$CHAIN" -p tcp -j REJECT --reject-with tcp-reset
  iptables -A "$CHAIN" -j REJECT --reject-with icmp-admin-prohibited
}

purge_input_rules() {
  # Remove every INPUT rule bound to the jail bridge (incl. stale LAB_ALLOW exceptions).
  { iptables -S INPUT | grep -- "-i $BR " || true; } | sed 's/^-A /-D /' | while read -r rule; do
    eval "iptables $rule" || true
  done
}

hook_chains() {
  # Forwarded traffic leaving the jail bridge.
  iptables -C DOCKER-USER -i "$BR" -j "$CHAIN" 2>/dev/null || iptables -I DOCKER-USER 1 -i "$BR" -j "$CHAIN"
  # Traffic from the jail to the VM itself (host services, SSH, the API, the VM public IP).
  iptables -A INPUT -i "$BR" -m conntrack --ctstate NEW -m limit --limit 20/min -j LOG --log-prefix "IOC-JAIL-HOST " --log-level 4
  iptables -A INPUT -i "$BR" -m conntrack --ctstate NEW -j REJECT --reject-with icmp-admin-prohibited
}

up() {
  command -v docker >/dev/null || { echo "docker is required"; exit 1; }
  iptables -L DOCKER-USER -n >/dev/null 2>&1 || { echo "DOCKER-USER chain missing: is dockerd running with iptables?"; exit 1; }
  ensure_network
  purge_input_rules
  reset_chain
  build_rules
  hook_chains
  # Belt and braces: no IPv6 out of the jail.
  sysctl -q -w "net.ipv6.conf.$BR.disable_ipv6=1" 2>/dev/null || true
  log "jail active on $BR"
  status
}

down() {
  iptables -D DOCKER-USER -i "$BR" -j "$CHAIN" 2>/dev/null || true
  purge_input_rules
  iptables -F "$CHAIN" 2>/dev/null || true
  iptables -X "$CHAIN" 2>/dev/null || true
  log "rules removed (network $NET kept)"
}

status() {
  echo "--- DOCKER-USER"; iptables -L DOCKER-USER -n --line-numbers | head -20
  echo "--- $CHAIN";      iptables -L "$CHAIN" -n -v --line-numbers 2>/dev/null | head -60
  echo "--- INPUT (jail)"; iptables -L INPUT -n -v | grep -E "$BR|IOC" || true
}

case "${1:-up}" in
  up) up ;;
  down) down ;;
  status) status ;;
  *) echo "usage: $0 [up|down|status]"; exit 2 ;;
esac
