#!/usr/bin/env bash
# Laptop-side helpers that act on the VM created by infra/terraform.
#   scripts/tf-remote.sh sync       rsync this repo to the VM (private repos / local changes)
#   scripts/tf-remote.sh bootstrap  run infra/vm/bootstrap.sh on the VM
#   scripts/tf-remote.sh env        write the Terraform-created inference key into the VM's .env
#   scripts/tf-remote.sh status     cloud-init + bootstrap + network state
#   scripts/tf-remote.sh tunnel     forward localhost:8000 -> VM API over SSH
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TF_DIR="$ROOT/infra/terraform"
tfo() { terraform -chdir="$TF_DIR" output -raw "$1"; }

IP="$(tfo public_ip)"
USER_="$(tfo admin_user)"
DIR="$(tfo repo_dir)"
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o ServerAliveInterval=30)
SSH=(ssh "${SSH_OPTS[@]}" "$USER_@$IP")

case "${1:-}" in
  sync)
    rsync -az --delete -e "ssh ${SSH_OPTS[*]}" \
      --exclude .git --exclude .venv --exclude .env --exclude 'data/scans' \
      --exclude 'infra/terraform/.terraform' --exclude '*.tfstate*' --exclude 'terraform.tfvars' \
      "$ROOT/" "$USER_@$IP:$DIR/"
    echo "synced -> $USER_@$IP:$DIR"
    ;;
  bootstrap)
    "${SSH[@]}" "set -a; . /etc/ioc-sentinel/provision.env; set +a; sudo -E $DIR/infra/vm/bootstrap.sh 2>&1 | tee -a /tmp/ioc-bootstrap.log"
    ;;
  env)
    KEY="$(tfo inference_api_key 2>/dev/null || true)"
    [[ -n "$KEY" && "$KEY" != "null" ]] || { echo "no inference_api_key output (create_inference=false?)"; exit 1; }
    # Key travels over SSH stdin only: never in argv, shell history or user-data.
    printf '%s' "$KEY" | "${SSH[@]}" "set -e; f=$DIR/.env; [ -f \$f ] || cp $DIR/.env.example \$f; chmod 600 \$f
      k=\$(cat); grep -q '^VULTR_INFERENCE_API_KEY=' \$f \
        && sed -i \"s|^VULTR_INFERENCE_API_KEY=.*|VULTR_INFERENCE_API_KEY=\$k|\" \$f \
        || echo \"VULTR_INFERENCE_API_KEY=\$k\" >> \$f
      echo 'VULTR_INFERENCE_API_KEY written to' \$f"
    ;;
  status)
    "${SSH[@]}" "cloud-init status --long; echo; cat /var/log/ioc-network.log; echo; tail -n 15 /var/log/ioc-bootstrap.log 2>/dev/null; echo; docker network ls --filter name=ioc-jail 2>/dev/null; command -v runsc && echo gvisor-ok || true"
    ;;
  tunnel)
    echo "API at http://localhost:8000/docs (Ctrl-C to close)"
    ssh "${SSH_OPTS[@]}" -N -L 8000:127.0.0.1:8000 "$USER_@$IP"
    ;;
  *)
    sed -n '2,8p' "$0"; exit 2 ;;
esac
