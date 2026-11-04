# IoC Sentinel

**An agent that investigates suspicious domains and produces Indicator-of-Compromise reports - without ever letting the suspicious content touch anything that matters.**

Built for the **Vultr Agent Rush Hackathon - Track 01 · Blast Radius Zero**.

> An agent that only chats is a demo; an agent that executes safely is a product.

## How it works

```
 Analyst ──► Web dashboard ──► FastAPI orchestrator (Vultr Cloud Compute VM)
                                   │  secrets live here only
                                   ├──► Vultr Serverless Inference (agent reasoning, tool calls)
                                   ├──► Host-side threat-intel tools (urlscan, VT, URLhaus, crt.sh, DNS)   [Day 2]
                                   └──► docker-py ──► Ephemeral sandbox (1 per URL)
                                                       Playwright/Chromium, non-root, read-only rootfs,
                                                       cap-drop ALL, no-new-privs, mem/cpu/pids caps,
                                                       tmpfs scratch, optional gVisor (runsc)
                                                       network: ioc-jail  ─► public Internet :80/:443 only
                                                                          ✕ 169.254.169.254 (metadata)
                                                                          ✕ RFC1918 / VPC / the VM itself
```

**Trusted vs. untrusted split.** Anything that needs a credential runs on the host as an agent tool.
Anything that *touches the suspicious target* runs in the sandbox, which has zero secrets and a jailed network.
Page content returned by the sandbox is treated as untrusted data (prompt-injection aware).

## What the sandbox returns (per URL)

- Screenshot (PNG) and HAR (metadata only, no bodies)
- Redirect chain, final URL, HTTP status, TLS certificate details
- Every host contacted, server IPs, raw-IP requests, failed/blocked requests
- Forms (password fields + cross-domain `action` = credential-harvest signal), scripts, iframes, favicon
- Downloads hashed (SHA-256/MD5) in a `noexec` tmpfs and discarded
- **Containment self-probe**: proves from inside that metadata, VPC and host are unreachable
- A timestamped **Containment Log** merging host lifecycle (spawn → limits → kill/OOM → destroy) and sandbox events

## Repo layout

```
apps/api/            FastAPI orchestrator, sandbox runner (docker-py), URL guard, inference client
sandbox/browser/     Sandbox image: Playwright worker (one URL in, one JSON line out)
infra/terraform/     Vultr provider: VPC, edge firewall, VM (cloud-init), Serverless Inference subscription
infra/vm/            bootstrap.sh (Ubuntu 24.04), jail-network.sh (iptables), gvisor.sh
infra/systemd/       ioc-jail.service (re-applies the jail on boot)
scripts/             check_models.py (Vultr capability matrix), smoke.sh (Day-1 acceptance)
demo/traps/          Fictional-brand trap page: credential form, metadata SSRF, prompt injection, drive-by download
docs/                Runbooks and the verified model matrix
```

## Quick start

```bash
# laptop: infrastructure as code (see docs/INFRA.md)
export VULTR_API_KEY=...
cp infra/terraform/terraform.tfvars.example infra/terraform/terraform.tfvars   # set admin_cidrs
make tf-init tf-plan tf-apply          # VPC + firewall + VM + inference subscription
make tf-sync tf-bootstrap tf-env       # code, hardening, jail, gVisor, inference key

# on the VM
make check-models                      # which models do tool calling / vision
make smoke                             # sandbox + containment probes must all be blocked
make api                               # then `make tf-tunnel` from the laptop -> localhost:8000/docs
```

## Status

- [x] Day 1 - VM bootstrap, jail network, hardened ephemeral sandbox, screenshot + HAR + IoC observations, containment log
- [ ] Day 2 - Agent loop on Vultr Serverless Inference + host-side threat-intel tools
- [ ] Day 3 - IoC consolidation, phishing signals, STIX 2.1 / JSON / HTML report
- [ ] Day 4 - Dashboard with live Containment Log, gVisor by default
- [ ] Day 5 - Demo traps, video, submission
