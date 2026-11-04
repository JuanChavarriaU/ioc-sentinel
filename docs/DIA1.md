# Día 1 - Runbook (VM + jail + sandbox)

Objetivo del día: una VM en Vultr donde `make smoke` pase. Es decir, el sandbox visita una URL,
devuelve screenshot + HAR + observaciones, **todos los probes de contención salen bloqueados**
y no queda ningún contenedor vivo.

## 1. Crear la VM

**Recomendado: Terraform**, ver `docs/INFRA.md` (`make tf-init tf-plan tf-apply tf-sync tf-bootstrap tf-env`). Eso cubre los pasos 1 y 2, y la key del paso 3. Lo de abajo es el camino manual por consola.

### Manual (consola Vultr)

- Products → Compute → **Cloud Compute** (Shared CPU o Regular Performance).
- Ubuntu **24.04 LTS x64**. Mínimo **2 vCPU / 4 GB** (Chromium + Docker build). Región: Miami o Atlanta (menor latencia desde Panamá).
- Agrega tu SSH key. Activa **VPC** si quieres (la red 10.x igual queda bloqueada desde la jail).
- Créditos: $200 cubren de sobra 5 días con una VM de ~$24/mes.

## 2. Bootstrap

```bash
ssh root@<IP>
adduser juanjo && usermod -aG sudo juanjo   # opcional, recomendado
git clone <tu-repo> ioc-sentinel && cd ioc-sentinel
sudo WITH_GVISOR=1 ./infra/vm/bootstrap.sh
```

Esto instala Docker (repo oficial), endurece `daemon.json`, configura ufw (22/80/443),
crea la red `ioc-jail` con sus reglas iptables (y el servicio systemd que las reaplica al bootear),
construye la imagen del sandbox y el venv de la API.

## 3. Inference: verificar modelos (¡antes de diseñar el Día 2!)

- Consola Vultr → Serverless → **Inference** → Add Serverless Inference → copia la API key.
- `nano .env` → `VULTR_INFERENCE_API_KEY=...`
- `make check-models` → imprime la matriz *tool calling / vision* y la guarda en `docs/models.json`.
  - La doc de Vultr dice que tool calling hoy solo está en `kimi-k2-instruct`. Confírmalo aquí.
  - Si ningún modelo tiene visión → el veredicto visual del Día 3 va por pHash + señales DOM.

## 4. Smoke test (criterio de "Día 1 terminado")

```bash
make smoke                                  # contra https://example.com
make scan URL=https://<dominio-sospechoso>  # cualquier otro
```

Debe mostrar en el Containment Log:

```
[host   ] spawn              {... "secrets_passed": 0}
[sandbox] containment_probe  cloud-metadata 169.254.169.254:80  blocked(No route to host)
[sandbox] containment_probe  docker-host-ssh 172.30.0.1:22      blocked(...)
...
[host   ] destroyed          {"ms": ~10}
```

Y `make jail-status` muestra los contadores de los REJECT subiendo.

## 5. Probar la página trampa (opcional hoy, obligatorio el Día 5)

En local (VM), con excepción de laboratorio en la jail:

```bash
LAB_ALLOW=172.30.0.1:8088 make jail
make traps &                                     # sirve demo/traps en :8088
cd apps/api && ../../.venv/bin/python -m app.sandbox.runner http://172.30.0.1:8088/ --allow-private
make jail                                        # vuelve a cerrar la excepción
```

Para el video conviene hospedar `demo/traps/` en un dominio público aparte (GitHub Pages sirve):
la jail bloquea el tráfico del sandbox hacia la propia VM, así que lo ideal es que la trampa no viva ahí.

## 6. gVisor

Si instalaste con `WITH_GVISOR=1`: pon `SANDBOX_RUNTIME=runsc` en `.env` y repite `make smoke`.
El evento `spawn` del log debe decir `"runtime": "runsc"`.

## Lo que ya quedó probado

Sin VM Vultr todavía, con la jail y el runner reales en un host Ubuntu 24.04 y la página trampa:

| Ataque desde la página | Resultado en la jail |
|---|---|
| `fetch` a `169.254.169.254/v1.json` (metadata Vultr) | `ERR_ADDRESS_UNREACHABLE` |
| `fetch` a `10.0.0.1` (VPC) | `ERR_ADDRESS_UNREACHABLE` |
| `fetch` al API del host `172.17.0.1:8000` | `ERR_ADDRESS_UNREACHABLE` |
| Formulario con password → dominio externo | detectado (`has_password`, `action` cross-domain) |
| Descarga drive-by | SHA-256 + MD5 calculados en tmpfs `noexec`, archivo descartado |
| Texto oculto con prompt injection | capturado como **dato** en `text_excerpt` (para la defensa del Día 2) |
| Timeout forzado (4 s) | `timeout_kill` → `destroyed` en ~11 ms, 0 contenedores huérfanos |

Bug encontrado y corregido: el tmpfs de `/tmp` necesita `mode=1777`, si no el usuario sin privilegios no puede escribir.
