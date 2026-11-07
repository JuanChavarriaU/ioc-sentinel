# Infraestructura con Terraform (proveedor `vultr/vultr` ~> 2.33)

Todo vive en `infra/terraform/`. Corre los comandos desde tu laptop, en WSL o Git Bash: los scripts auxiliares son bash.

## Qué crea

| Recurso | Para qué |
|---|---|
| `vultr_vpc.main` (10.40.0.0/24) | Red privada para el plano de control y los futuros workers/DB. No se solapa con la jail (172.30.0.0/24) ni con Docker (172.17/16). |
| `vultr_firewall_group` + reglas | Edge firewall: 22 solo desde `admin_cidrs`, 80/443 públicos, ICMP. 8000 solo si `expose_api_port = true`. |
| `vultr_ssh_key.admin` | Tu llave pública. |
| `vultr_instance.control_plane` | Ubuntu 24.04, `vc2-2c-4gb`, IPv4 solamente, conectada a la VPC. Cloud-init crea tu usuario sudo y desactiva root y passwords. |
| `vultr_inference.agent` | Suscripción de Serverless Inference. Su `api_key` sale como output sensible. |
| `vultr_reserved_ip` (opcional) | IP pública estable entre rebuilds, para el DNS de la demo. |

### Por qué la VPC no debilita la contención

La jail del sandbox rechaza **todo** 10.0.0.0/8, así que una página maliciosa no puede pivotar hacia la VPC, aunque la VM sí esté conectada a ella. La VPC queda para tráfico entre componentes confiables: más adelante, un nodo worker de sandboxes separado o una DB administrada. Esta separación es un buen punto para el pitch: el *blast radius* es un contenedor, nunca la red.

### Sin secretos en `user_data`

Vultr sirve el `user_data` desde el servicio de metadata, `169.254.169.254`, justo lo que la jail bloquea. Aun así, la key de inference **no** pasa por ahí: `make tf-env` la escribe en `.env` por stdin de SSH (chmod 600).

## Flujo

```bash
export VULTR_API_KEY=...                 # Vultr -> Account -> API (habilita tu IP en el Access Control de la API)
cd infra/terraform && cp terraform.tfvars.example terraform.tfvars
#   edita admin_cidrs = ["<tu IP>/32"]   (curl -s https://ifconfig.me)
cd ../..
make tf-init
make tf-plan
make tf-apply

# Repo privado (o cambios locales sin push):
make tf-sync          # rsync del repo a /opt/ioc-sentinel
make tf-bootstrap     # Docker, gVisor, jail, ufw (+VPC), imagen sandbox, venv

make tf-env           # key de inference -> .env en la VM
make tf-status        # cloud-init, IPs (debe aparecer 10.40.0.x), jail, gVisor
make tf-ssh           # luego, dentro: cd /opt/ioc-sentinel && make check-models && make smoke
make tf-tunnel        # http://localhost:8000/docs sin abrir el puerto
```

Con un **repo público**, pon `repo_url` en `terraform.tfvars`: cloud-init clona y corre el bootstrap en el primer arranque. Sigue el progreso con `make tf-status` o `tail -f /var/log/ioc-bootstrap.log`.

## Costos y limpieza

- VM `vc2-2c-4gb` ≈ US$20/mes, prorrateado por hora, así que unos pocos dólares en 5 días. VPC y firewall no tienen costo. Inference se cobra por uso.
- Al terminar la hackathon: `make tf-destroy`.

## Notas

- `user_data` está en `ignore_changes`: cloud-init solo corre en el primer boot. Para cambiar el provisioning, usa `make tf-sync tf-bootstrap`, o `terraform apply -replace=vultr_instance.control_plane`.
- Cambiar `hostname` fuerza la recreación de la instancia (comportamiento del proveedor).
- El state queda local (`*.tfstate`, git-ignored) y contiene la API key de inference. Si trabajas en equipo, muévelo a un backend S3, que puede ser Vultr Object Storage.
- Si la VPC no aparece en `make tf-status`, revisa `ip -4 addr` en la VM. La imagen de Vultr la configura por cloud-init. Si no la configurara, avísame y agregamos el netplan.
