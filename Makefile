SHELL := /bin/bash
PY ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
URL ?= https://example.com

.PHONY: help bootstrap gvisor jail jail-status jail-down sandbox-image check-models scan smoke api traps

help:
	@grep -E '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n",$$1,$$2}'

bootstrap: ## (VM, sudo) Docker + jail + ufw + sandbox image + venv
	sudo ./infra/vm/bootstrap.sh

gvisor: ## (VM, sudo) install gVisor runsc runtime
	sudo ./infra/vm/gvisor.sh

jail: ## (VM, sudo) create/refresh jail network + iptables
	sudo --preserve-env=LAB_ALLOW,SANDBOX_DNS ./infra/vm/jail-network.sh up

jail-status: ## show jail rules + hit counters
	sudo ./infra/vm/jail-network.sh status

jail-down: ## remove jail iptables rules
	sudo ./infra/vm/jail-network.sh down

sandbox-image: ## build the sandbox browser image
	docker build -t ioc-sentinel/sandbox-browser:latest sandbox/browser

check-models: ## list Vultr inference models + probe tool calling / vision
	$(PY) scripts/check_models.py --probe

scan: ## run one URL through the sandbox:  make scan URL=https://...
	set -a; [[ -f .env ]] && . ./.env; set +a; cd apps/api && ../../$(PY) -m app.sandbox.runner "$(URL)"

smoke: ## Day-1 acceptance test
	./scripts/smoke.sh $(URL)

api: ## run the FastAPI orchestrator on :8000
	set -a; [[ -f .env ]] && . ./.env; set +a; $(PY) -m uvicorn app.main:app --app-dir apps/api --host 0.0.0.0 --port 8000

traps: ## serve demo trap pages on :8088 (use with LAB_ALLOW=172.30.0.1:8088 make jail)
	cd demo/traps && head -c 4096 /dev/urandom > invoice.bin && python3 -m http.server 8088
