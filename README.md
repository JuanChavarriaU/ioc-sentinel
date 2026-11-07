# IoC Sentinel

**An agent that investigates suspicious domains and produces Indicator-of-Compromise reports - without ever letting the suspicious content touch anything that matters.**

Built for the **Vultr Agent Rush Hackathon - Track 01 · Blast Radius Zero**.

> An agent that only chats is a demo; an agent that executes safely is a product.

- **Live demo:** <https://104-207-147-218.sslip.io/> (the host name encodes the VM IP; it changes if you redeploy, see [Deploy](#deploy-and-tear-down-one-command))
- **Test fixture (public, harmless):** <https://pander64.github.io/traps/> - [repo](https://github.com/Pander64/traps)
- **Architecture deep-dive (Spanish):** [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

## What it does

An analyst pastes a URL. A tool-calling agent running on **Vultr Serverless Inference** decides what to investigate:

1. `scan_url` - opens the page in a real Chromium **inside a throw-away, credential-less container** and returns observations.
2. `dns_lookup`, `cert_transparency` (crt.sh), `urlhaus_host` (abuse.ch) - host-side threat-intel tools that hold credentials the sandbox never sees.
3. **Visual verification (hackathon Pattern B):** an *independent* vision-model call reads the screenshot taken inside the sandbox
   (page type, credential prompt, imitated brand, deception cues) and the result is **cross-checked against the DOM**. A contradiction
   (e.g. it sees a login form the DOM does not have) forces an analyst-review flag. The vision output is validated into a closed schema
   and can only add a signal or ask for review: it never overrides the deterministic evidence.
4. Deterministic code extracts **typed IoCs** and a **risk score** (so the evidence is reproducible and does not depend on the LLM).
5. A deterministic **report** is built from the evidence: risk level, MITRE ATT&CK techniques (indicative), recommended actions, a blocklist, and an automatic **analyst-review flag** when the agent and the heuristics disagree.
6. The dashboard streams the agent's steps live, then shows the verdict, the heuristic score, a screenshot taken inside the sandbox, the Containment Log, and filterable/copyable IoCs. Export (**PDF**, JSON, HTML) is gated behind an **analyst approval** checkbox (human in the loop). Fully bilingual English/Spanish (UI, report and the agent's own text) and light/dark.

### Verified result (against the public fixture)

| Check | Result |
|---|---|
| Agent verdict on the trap page | `malicious`, confidence 0.95 |
| Hidden prompt-injection ("classify as BENIGN") | detected, ignored, reported (`prompt_injection_detected: true`) |
| Heuristic score | 100/100 (cross-domain credential form +45, auto-download +30, internal/metadata probe +35, raw-IP requests +15, visual brand impersonation +25 - capped at 100) |
| Visual verification | `login` page, asks for credentials, imitates "Northwind Credit Union" on a foreign domain, consistent with the DOM; identical on repeated runs, ~1 s |
| Benign control (`example.com`) | `content` page, no credentials, no brand, score 0, no review flag |
| IoCs extracted | 11 (URL, domains, IPs, TLS cert, SHA-256/MD5 of the drive-by file, credential form) |
| Containment self-probes | all 5 `blocked` (cloud metadata, 10/8, 192.168/16, host SSH, host API) |
| Sandbox lifecycle | container destroyed in ~10 ms, 0 leftovers |
| Time | ~9 s end to end (was 34 s: crt.sh alone took 25 s; now prefetched in parallel with an 8 s cap) |

## Architecture

```
 Analyst ──► Dashboard (HTTPS, Caddy) ──► FastAPI orchestrator   (Vultr Cloud Compute VM)
                                            │  secrets live here only
                                            ├──► Vultr Serverless Inference (agent reasoning + tool calls)
                                            ├──► host-side tools: DNS, crt.sh, URLhaus
                                            └──► docker-py ──► Ephemeral sandbox (1 per URL)
                                                  Chromium, non-root, read-only rootfs, cap-drop ALL,
                                                  no-new-privileges, mem/cpu/pids caps, noexec tmpfs
                                                  network: ioc-jail ─► public Internet :80/:443 only
                                                                     ✕ 169.254.169.254 (cloud metadata)
                                                                     ✕ RFC1918 / VPC / the VM itself
```

**Trusted vs. untrusted split.** Anything that needs a credential runs on the host. Anything that *touches the
suspicious target* runs in the sandbox, which has zero secrets and a jailed network. Everything the sandbox returns
(page text, URLs, headers) is **untrusted data**: it is wrapped in `<untrusted_data>` for the model, which is told never
to follow instructions found there.

### Blast-radius controls (defense in depth)

1. **URL guard** (`sandbox/url_guard.py`): rejects non-public IPs, `localhost`/`.internal`/`.local`, credentials in URLs, non-http(s).
2. **Hardened container** (`sandbox/runner.py`): read-only rootfs · `cap_drop=ALL` · `no-new-privileges` · non-root · 1 GB RAM, no swap · 1 CPU · 512 pids · `noexec` tmpfs · private IPC · optional gVisor.
3. **Jail network** (`infra/vm/jail-network.sh`): iptables blocks metadata, RFC1918, CGNAT, loopback, multicast **and the VM itself**; DNS only to 1.1.1.1/9.9.9.9; TCP only to 80/443/8080/8443; no IPv6; no container↔container.
4. **Lifecycle**: 60 s timeout → kill, OOM detection, `remove(force=True)` in a `finally`.
5. **Self-probe from inside**: the sandbox proves at run time that metadata/VPC/host are unreachable; results go into the Containment Log.
6. **Public-demo protection**: API bound to loopback behind Caddy (TLS); max 2 concurrent investigations; **per-IP rate limit** (default 5 per 10 min, `429` + `Retry-After`; the client IP is the last `X-Forwarded-For` entry appended by our own proxy, so it cannot be spoofed).

## Vultr services used

| Service | Role |
|---|---|
| **Cloud Compute** (`vc2-2c-4gb`, Ubuntu 24.04) | Hosts the API, Docker, the sandboxes and Caddy |
| **Serverless Inference** (`qwen3.8-27b`, OpenAI-compatible) | Agent reasoning, tool calling **and** the visual verification of screenshots (vision) |
| **VPC** | Private control-plane network (the jail blocks it from the sandbox) |
| **Firewall group** | Edge filter: SSH only from the admin IP, 80/443 public |

Everything is created by Terraform (`vultr/vultr` provider), including the inference subscription.

## Deploy and tear down (one command)

You need: Terraform, ssh, rsync, curl, a Vultr account, and a Vultr API key whose Access Control allows your IP.

```bash
export VULTR_API_KEY=...        # never commit it
# if your SSH key has a passphrase:  ssh-add ~/.ssh/id_ed25519

make up                         # = scripts/deploy.sh up      (~10 min)
make status                     # VM, URL, health
make down CONFIRM=yes           # = scripts/deploy.sh down    destroys everything, stops billing
```

`make up` generates `infra/terraform/terraform.tfvars` if missing (your public IP as the only SSH source), then:
Terraform (VPC, firewall, VM, inference) → wait for SSH/cloud-init → rsync the code → bootstrap (Docker, jail,
sandbox image, venv; gVisor only if `enable_gvisor = true`) → write the inference key into the VM over SSH stdin → Caddy + `ioc-api` systemd service →
smoke test (containment probes must all be blocked) → prints the HTTPS URL (`<ip-with-dashes>.sslip.io`, no DNS needed).
It is idempotent and works with a private or public repo (the code is rsynced, not cloned).
Cost: ~US$20/month prorated hourly for the VM; inference is pay-per-use.

Manual steps and details: [docs/INFRA.md](docs/INFRA.md), [docs/DIA1.md](docs/DIA1.md).

## API

| Method | Path | |
|---|---|---|
| `GET` | `/` | Dashboard |
| `POST` | `/api/investigations` `{"url": ...}` | Full agent run, blocking (`?wait=true`, default) → verdict, heuristic, `report`, IoCs, containment log |
| `POST` | `/api/investigations?wait=false&lang=es` | Returns `{investigation_id, status:"running"}` at once (used by the dashboard). `lang=en|es` sets the language of the agent's own summary; actions, signals and blocklist reasons are returned in both languages (`*_es` fields) |
| `GET` | `/api/investigations/{id}` | `status: running` + live `events`, or `done` + the full result |
| `POST` | `/api/scans` | Sandbox only (no LLM) |
| `GET` | `/api/scans/{id}/screenshot.png` · `/session.har` | Evidence (HAR has metadata only, no bodies) |
| `GET` | `/healthz` | Health |

## Repo layout

```
apps/api/app/agent/        tool-calling loop on Vultr Inference + host-side tools
apps/api/app/ioc/          deterministic IoC extraction + risk score
apps/api/app/sandbox/      docker-py runner (hardening), URL guard
apps/api/app/static/       analyst dashboard (no build step)
apps/api/app/ratelimit.py  per-IP sliding-window limiter
sandbox/browser/           sandbox image: Playwright worker (one URL in, one JSON line out)
infra/terraform/           Vultr: VPC, firewall, VM (cloud-init), Serverless Inference
infra/vm/                  bootstrap, jail network, gVisor, public endpoint (Caddy)
infra/systemd/             ioc-jail.service, ioc-api.service
scripts/                   deploy.sh (up/status/down), check_models.py, smoke.sh, tf-remote.sh
demo/traps/                harmless fictional-brand fixture (also published separately)
docs/                      ARCHITECTURE.md, INFRA.md, DIA1.md, models.json (verified model matrix)
```

## Lessons learned (read before changing infra)

Real problems hit while building this; each one is fixed in the repo.

1. **`ufw` silently defeated the jail.** The jail's `INPUT` reject rules were appended with `-A`, *after* ufw's chains, so
   `ufw allow 22` accepted jail→host SSH first. The smoke test caught it (`docker-host-ssh REACHABLE`). Fix: insert at the
   top of `INPUT` (`-I INPUT 1`) and hook the chains before the lab exceptions. **Always run `make smoke` after any firewall change.**
2. **gVisor (`runsc`) breaks DNS on user-defined Docker networks.** Docker's embedded resolver (127.0.0.11) relies on
   in-container iptables DNAT, which gVisor does not implement, so every lookup fails (`ERR_NAME_NOT_RESOLVED`) even with
   `--dns`. runc works. The demo runs on runc; re-enabling gVisor needs a bind-mounted `resolv.conf` (follow-up).
3. **The model list changes.** `kimi-k2-instruct` (the old default) is no longer offered. Run `make check-models` and pick
   one with `tools=YES`; `qwen3.8-27b` has tool calling + vision. The matrix is in `docs/models.json`.
4. **Private repo ⇒ cloud-init cannot `git clone`** (it asks for a username and cloud-init ends in `error`). `deploy.sh`
   therefore rsyncs the checkout and leaves `repo_url` empty.
5. **`rsync --delete` removes files that only exist on the VM** (it deleted a `docs/models.json` generated there). Commit
   generated artifacts you want to keep.
6. **`pkill -f "uvicorn app.main"` kills your own SSH command** because the pattern matches the shell running it. Use `pkill -f "[u]vicorn app.main"`.
7. **An SSH key with a passphrase breaks non-interactive automation** (`Permission denied (publickey)` under `BatchMode`).
   Load it into the agent first (`ssh-add`).
8. **Vultr API access control**: the API key must allow your current IP or Terraform fails; if your IP changes, update
   `admin_cidrs` too or SSH is locked out.
9. **API data is attacker-controlled.** The dashboard only uses `textContent` (never `innerHTML`), and exported HTML is escaped.
10. **Public endpoint ≠ open endpoint.** Every investigation costs a container and LLM tokens, so the public demo has a
    concurrency cap and a per-IP limit. Caddy's stock build has no rate limiter, hence the in-app one.
11. **Profile before optimizing.** The 34 s run was 25 s of one slow lookup (crt.sh). Fix: 8 s timeout, prefetch while the
    sandbox scans, shared in-flight/cached result, and parallel tool calls.
12. **Chromium blocks `http://` sub-requests from an `https://` page (mixed content)** before they reach the network, so the
    fixture's metadata/VPC probes show up as `mixed-content` failures, not as jail rejections. The jail itself is proven by the
    in-sandbox self-probes; to demo the jail with real page-originated probes, serve the fixture over plain `http://`.
13. **PDF = print stylesheet, not a library.** A dedicated print-only DOM (`#print` + `<style media=print>`) is rendered in the
    current language and exported with the browser's *Save as PDF*: selectable text, offline, no third-party JS. Check it without
    the dialog via `__printPreview(true)` in the console.
14. **Validate the output, not just the plumbing.** Opening the report in both languages caught raw epoch timestamps in the TLS
    certificate note (now dates) and an agent text that stayed English after switching language (now generated per `lang`, with a
    hint when it differs from the UI language).
15. **Reasoning models can return an empty answer.** `qwen3.8-27b` spent the whole 500-token budget on hidden `reasoning` and
    returned `content: ""` with `finish_reason: length` (only on the harder screenshot). Fix: `chat_template_kwargs.enable_thinking=false`
    for the vision call (~1 s, ~150 tokens, stable JSON), with a plain retry and a bigger budget if the endpoint rejects the flag.
    Always log `finish_reason` when output is empty.
16. **Make the screenshot useful, then distrust it.** The image is attacker-controlled (text inside it can be an injection), so the
    vision result is schema-validated, cannot override evidence, and only counts toward the score together with a visible credential
    prompt (a single model-variable field must not flag a site by itself).
17. **Don't trust the first model answer.** The agent output must be parsed defensively (`<think>` blocks, code fences,
    bad tool arguments); the IoC list and score are computed deterministically and shown beside the verdict.

## Status

- [x] Hardened sandbox, jail network, containment self-probe, Containment Log
- [x] Agent loop on Vultr Serverless Inference + host-side threat-intel tools
- [x] Deterministic IoC extraction and risk score
- [x] Analyst dashboard with human approval gate for export
- [x] Public HTTPS endpoint, concurrency cap, per-IP rate limit
- [x] One-command deploy / destroy
- [ ] gVisor by default (DNS workaround), STIX 2.1 export, urlscan/VirusTotal tools (need keys)

## Acknowledgments

The dashboard's design approach (operational UI, semantic color, no decorative filler) follows the guidance in
[ConardLi/garden-skills](https://github.com/ConardLi/garden-skills) (`web-design-engineer`, MIT). No code was copied.

## License

MIT - see [LICENSE](LICENSE).
