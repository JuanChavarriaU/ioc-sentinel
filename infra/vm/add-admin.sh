#!/usr/bin/env bash
# Add another admin user to an ALREADY RUNNING VM (same powers as the first one: sudo without password + docker).
# Run it as an existing admin:   sudo ./infra/vm/add-admin.sh <username> "<ssh public key>"
# Example:                       sudo ./infra/vm/add-admin.sh juanjo "ssh-ed25519 AAAA... juanjo@laptop"
# Also remember to allow the new admin's public IP on the Vultr firewall (port 22), see docs/INFRA.md.
set -euo pipefail

USER_NEW="${1:-}"; PUBKEY="${2:-}"
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
[[ "$USER_NEW" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || { echo "usage: $0 <username> \"<ssh public key>\"" >&2; exit 2; }
[[ "$PUBKEY" =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-[a-z0-9]+)\ [A-Za-z0-9+/=]+ ]] || { echo "second argument must be a public key (ssh-ed25519 AAAA...)" >&2; exit 2; }

id "$USER_NEW" >/dev/null 2>&1 || adduser --disabled-password --gecos "" "$USER_NEW"
usermod -aG sudo "$USER_NEW"
getent group docker >/dev/null && usermod -aG docker "$USER_NEW"
echo "$USER_NEW ALL=(ALL) NOPASSWD:ALL" >"/etc/sudoers.d/90-$USER_NEW"
chmod 440 "/etc/sudoers.d/90-$USER_NEW"; visudo -cf "/etc/sudoers.d/90-$USER_NEW" >/dev/null

install -d -m 700 -o "$USER_NEW" -g "$USER_NEW" "/home/$USER_NEW/.ssh"
AK="/home/$USER_NEW/.ssh/authorized_keys"
grep -qxF "$PUBKEY" "$AK" 2>/dev/null || echo "$PUBKEY" >>"$AK"
chown "$USER_NEW:$USER_NEW" "$AK"; chmod 600 "$AK"

# sshd only lets the users listed in AllowUsers in (hardening). Add the new one.
CONF=/etc/ssh/sshd_config.d/10-ioc-hardening.conf
if grep -q '^AllowUsers' "$CONF"; then
  grep -E '^AllowUsers.*\b'"$USER_NEW"'\b' "$CONF" >/dev/null || sed -i "s/^AllowUsers.*/& $USER_NEW/" "$CONF"
else
  echo "AllowUsers $USER_NEW" >>"$CONF"
fi
sshd -t && systemctl reload ssh

# Shared repo checkout: let the new admin write it (the first admin owns it).
REPO=/opt/ioc-sentinel
if [[ -d "$REPO" ]]; then
  OWNER="$(stat -c %U "$REPO")"
  setfacl -R -m "u:$USER_NEW:rwX" -m "d:u:$USER_NEW:rwX" "$REPO" 2>/dev/null \
    || echo "note: install 'acl' or chown $REPO yourself if $USER_NEW must edit it (owner: $OWNER)"
fi
echo "OK: $USER_NEW can ssh in (if the Vultr firewall allows their IP) and has sudo + docker."
grep '^AllowUsers' "$CONF"
