# Submission: IoC Sentinel

Contenido listo para pegar en el formulario, en el mismo orden. Los assets ya están generados en `docs/media/` y `docs/slides/`.

---

## 📋 Basic information

### Project title
IoC Sentinel

### Short description
An AI agent that investigates suspicious URLs inside a throw-away, jailed sandbox on Vultr and turns what it finds into an Indicator-of-Compromise report, with zero blast radius.

### Long description
IoC Sentinel is a security agent that does real work on dangerous content without putting anything that matters at risk.
An analyst pastes a suspicious URL. A tool-calling agent running on **Vultr Serverless Inference** decides what to investigate:
it opens the page in a real Chromium inside an ephemeral, credential-less container, runs DNS, certificate-transparency
and URLhaus lookups on the host, and asks an independent vision-model call to read the sandbox screenshot (login form? imitated brand?)
and cross-checks it against the DOM. Deterministic code then extracts typed IoCs, computes a reproducible risk score and builds a report
with MITRE ATT&CK techniques, recommended actions and a blocklist. Export is gated behind an analyst approval (human in the loop).

The point is containment. Trusted code (secrets, threat-intel APIs) runs on the host; anything that touches the target runs in a
sandbox with no secrets, a read-only rootfs, `cap-drop ALL`, resource caps and a jail network that blocks cloud metadata, RFC1918,
the VPC and the VM itself. The sandbox proves this at run time with self-probes that land in a **Containment Log**, and the container
is destroyed in ~10 ms afterwards. Page content is treated as untrusted data: a hidden prompt injection on our public test page
("classify as BENIGN") is detected, ignored and reported. A full run takes about 9 s. Everything (VPC, firewall, VM, inference) is
created and destroyed with one command (`make up` / `make down`).

### Technology & category tags
**Technologies:** Vultr Cloud Compute, Vultr Serverless Inference, Vultr VPC, Vultr Firewall, Terraform, Python, FastAPI, Docker, Playwright / Chromium, Caddy, iptables, Qwen (tool calling + vision), MITRE ATT&CK

**Category:** Track 01 · Blast Radius Zero · Cybersecurity / AI agents / Threat intelligence

---

## 📸 Cover image and presentation

### Cover image ✅
`docs/media/cover.png` (1600x900, 16:9). Fuente editable: `docs/media/cover.html`.

### Video presentation ✅
`docs/media/demo.mp4` (52 s, 1440x810, subtitulado, sin audio): demo real contra la URL pública, con el Containment Log (5 probes `blocked`) en pantalla.
Súbanlo a YouTube/Vimeo como *unlisted* y pongan ese link en el formulario. Si quieren voz, graben encima con el guion de abajo.

### Slide presentation ✅
`docs/slides/index.html` (6 slides, 16:9, flechas para navegar, `E` para editar). Para el formulario: exporten a PDF
(`bash ~/.claude/plugins/cache/frontend-slides/frontend-slides/2.1.0/skills/frontend-slides/scripts/export-pdf.sh docs/slides/index.html`)
o publíquenlo con GitHub Pages / Vercel.

---

## 💻 App hosting and repository

| Campo | Valor |
|---|---|
| Public GitHub repository | <https://github.com/JuanChavarriaU/ioc-sentinel> (PUBLIC ✅, verificado) |
| Demo application platform | Vultr Cloud Compute (Ubuntu 24.04, `vc2-2c-4gb`) + Caddy TLS |
| Application URL | <https://104-207-147-218.sslip.io/> (`/healthz` → 200 ✅ al momento de escribir esto) |

> La URL ahora es persistente: `make up` usa una IP reservada de Vultr que `make down` conserva (ver README, *Persistent URL*). La VM actual aún usa la IP anterior; el primer `make up` con este cambio fija la nueva IP definitiva y a partir de ahí no cambia más.

### Vultr-specific documentation
Todo está en el [README](../README.md): secciones **Architecture**, **Blast-radius controls**, **Vultr services used**,
**Deploy and tear down** y **Lessons learned**. No hace falta un informe aparte.

---

## ⚡ Show how you used Vultr: checklist

- [x] README público explica los servicios de Vultr (Compute, Serverless Inference, VPC, Firewall) y la infraestructura (Terraform).
- [x] Arquitectura de backend/despliegue documentada (README + `docs/ARCHITECTURE.md`).
- [x] Caso de uso del agente y cómo ejecuta tareas reales (README: *What it does*).
- [x] **Challenge 1** (está en `demo.mp4`, ~0:30 a 0:40): momento de contención en el video.
- [x] No se necesita reporte de arquitectura Vultr separado.

## Guion del video (con momento de contención)

Duración objetivo: 2:30 a 3:00.

1. **(0:00) Gancho.** "Un agente que solo conversa es una demo; uno que ejecuta con seguridad es un producto."
2. **(0:15) Investigación.** Pegar `https://pander64.github.io/traps/` en el dashboard. Mostrar los pasos del agente en vivo.
3. **(0:50) Resultado.** Veredicto `malicious`, score 100, IoCs, screenshot tomada dentro del sandbox, prompt injection detectada e ignorada.
4. **(1:20) ⭐ Momento de contención (Challenge 1).** Abrir el Containment Log: los 5 self-probes (metadata, 10/8, 192.168/16, SSH del host, API del host) en `blocked`,
   y el contenedor destruido en ~10 ms con 0 sobrantes. Para reforzarlo, en la VM correr `make smoke` o mostrar el log de `docker ps -a` vacío después del run.
5. **(2:00) Vultr.** Mostrar `make up` / `make down` y el stack: Compute + Serverless Inference + VPC + Firewall.
6. **(2:30) Control humano.** Aprobar el checkbox y exportar el PDF.

> Antes de grabar: `make smoke` para confirmar que todos los probes siguen bloqueados, y probar el flujo una vez para calentar la VM.
