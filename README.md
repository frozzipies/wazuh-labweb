# SOC Lab · Challenge 1 — Wazuh SIEM + Web-Attack Dataset

A self-contained, Dockerized **Wazuh SIEM** training lab. It boots the real
Wazuh dashboard + indexer (no manager, no agents, no filebeat) and
**automatically seeds a realistic web-attack dataset** so students can log in
and immediately start hunting.

> **Scenario:** a public web server has been probed and compromised over the
> last 24 hours. Students reconstruct the kill chain: recon → path traversal →
> SQL injection → XSS → web shell.

| | |
|---|---|
| **Stack** | Wazuh 4.12.0 (indexer + dashboard only) + a one-shot data seeder |
| **Dataset** | ~278 alerts, deterministic, all within the last 24h |
| **Attacks** | Forced browsing, path traversal, SQLi, XSS, web-shell RCE |
| **Deploy** | `docker compose` — VPS, Railway, Render, or any Docker host |

---

## Requirements

- **Docker** + **Docker Compose v2**
- **~1.5 GB RAM** (indexer 256 MB heap + dashboard ~500 MB + overhead)
- **~2-3 GB disk** (2 Docker images, no manager image needed)
- Linux kernel: `vm.max_map_count >= 262144` (handled by `setup.sh`)

## Quick start

```bash
./setup.sh
```

Watch the data load:

```bash
docker compose logs -f wazuh.seeder
```

Then open **https://localhost:5601** → log in → **Discover** → index pattern
**`wazuh-alerts-*`** → time range **Last 24 hours**.

| Dashboard | Username | Password |
|---|---|---|
| https://localhost:5601 | `admin` | `SecretPassword` |

## Who does what

| Service | Image | Role |
|---|---|---|
| `wazuh.indexer` | `wazuh/wazuh-indexer:4.12.0` | OpenSearch data store (256 MB heap) |
| `wazuh.dashboard` | `wazuh/wazuh-dashboard:4.12.0` | Real Wazuh UI (HTTPS, port 5601) |
| `wazuh.seeder` | built from `./seeder` | One-shot: loads attack dataset, then exits |

No manager, no filebeat, no agents — just the real Wazuh UI and the logs.

> Wazuh plugin pages that talk to the manager API (Agents, Rules, etc.) will
> show connection errors — that's expected. Students only need **Discover**
> to query `wazuh-alerts-*`.

## For students / instructors

- Student brief: [`docs/STUDENT_BRIEF.md`](docs/STUDENT_BRIEF.md)
- Answer key: [`docs/INSTRUCTOR_NOTES.md`](docs/INSTRUCTOR_NOTES.md)

## Reset for a new cohort

```bash
docker compose down -v
./setup.sh
```

## Deploying on a PaaS

### ngelinx — single container (Application + Dockerfile)

1. **New service → Application**, repo, branch `main`.
2. Container port: **5601**. Map your domain to it.
3. Give the app **~1.5 GB RAM**.
4. Open the domain → `admin` / `SecretPassword` → **Discover** → `wazuh-alerts-*`.

### ngelinx — Docker Compose

1. **New service → Docker Compose**, repo, branch `main`.
2. Expose **`wazuh.dashboard`** → **port 5601** → **backend HTTPS**.
3. Give it **~1.5 GB RAM**. Set `vm.max_map_count=262144` if indexer crash-loops.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Indexer exits / `max virtual memory areas` error | `sudo sysctl -w vm.max_map_count=262144` |
| Dashboard shows "no results" | Widen time range to *Last 24 hours*; check seeder logs |
| Wazuh plugin pages show API errors | Expected — no manager. Use **Discover**. |
| Seeder says "already seeded" | See *Reset* above |

## Credits

Built on [wazuh/wazuh-docker](https://github.com/wazuh/wazuh-docker) (v4.12.0).
The web-attack dataset and training materials are original to this lab.
