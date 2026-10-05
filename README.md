# SOC Lab · Challenge 1 — Wazuh SIEM + Web-Attack Dataset

A self-contained, Dockerized **Wazuh SIEM** training lab. It boots a full Wazuh
single-node stack (indexer + manager + dashboard) and **automatically seeds a
realistic web-attack dataset** so students can log in and immediately start
hunting a real-looking incident — no agents to deploy, no attacks to run.

> **Scenario:** a public web server has been probed and (spoiler, for
> instructors) compromised over the last 24 hours. Students reconstruct the
> kill chain: recon → path traversal → SQL injection → XSS → web shell.

| | |
|---|---|
| **Stack** | Wazuh 4.12.0 (indexer / manager / dashboard) + a one-shot data seeder |
| **Dataset** | ~278 alerts, deterministic, all within the last 24h |
| **Attacks** | Forced browsing, path traversal, SQLi, XSS, web-shell RCE |
| **Deploy** | `docker compose` — VPS, Railway, Render, or any Docker host |

---

## Prerequisites

- **Docker** + **Docker Compose v2** (`docker compose version`).
- **~4 GB RAM** free (the indexer alone wants ~1 GB heap; see tuning below).
- Linux kernel setting `vm.max_map_count >= 262144` (handled by `setup.sh` on
  hosts where you have `sudo`).

## Quick start (recommended)

```bash
./setup.sh
```

That script sets `vm.max_map_count`, generates the TLS certificates on first
run, builds the seeder, and starts everything. First boot takes **2–4 minutes**.

Watch the data load:

```bash
docker compose logs -f wazuh.seeder
# ...
# [+] Done. 278 alerts loaded. Open the dashboard and explore index pattern `wazuh-alerts-*`.
```

Then open **https://localhost** → log in → **Discover** → index pattern
**`wazuh-alerts-*`** → time range **Last 24 hours**.

| Dashboard | Username | Password |
|---|---|---|
| https://localhost | `admin` | `SecretPassword` |

> ⚠️ These are **insecure demo credentials for a throwaway training lab only.**
> Do not expose this stack to the public internet or reuse the passwords.

## Manual start (if you prefer)

```bash
# 1. kernel setting (once per host)
sudo sysctl -w vm.max_map_count=262144

# 2. generate certificates (first run only)
docker compose -f generate-indexer-certs.yml run --rm generator

# 3. bring everything up (Wazuh + seeder)
docker compose up -d --build
```

Docker Compose automatically merges `docker-compose.yml` (the stock Wazuh
single-node stack) with `docker-compose.override.yml` (our seeder).

## Who does what

| Service | Image | Role |
|---|---|---|
| `wazuh.indexer` | `wazuh/wazuh-indexer:4.12.0` | OpenSearch data store (port 9200) |
| `wazuh.manager` | `wazuh/wazuh-manager:4.12.0` | Analysis engine + API |
| `wazuh.dashboard` | `wazuh/wazuh-dashboard:4.12.0` | Web UI (port 443) |
| `wazuh.seeder` | built from `./seeder` | **One-shot**: loads the attack dataset, then exits |

The seeder waits for the indexer to be healthy, bulk-loads the dataset into
`wazuh-alerts-4.x-*`, and writes a marker so it **won't duplicate data** on
restart. The dataset generator is baked into the seeder image, so the lab is
fully self-contained and offline-reproducible.

## For students / instructors

- 👩‍🎓 **Student brief:** [`docs/STUDENT_BRIEF.md`](docs/STUDENT_BRIEF.md) — the
  scenario, mission questions, and hunting hints. Hand this out.
- 🔑 **Answer key:** [`docs/INSTRUCTOR_NOTES.md`](docs/INSTRUCTOR_NOTES.md) — the
  full kill chain, model answers, debrief points, and reset instructions.
  **Keep this from students.**

## Reset for a new cohort

```bash
docker compose down -v   # wipe indexed data
./setup.sh               # rebuild + reseed
```

## Deploying on a PaaS

This is a **multi-container** lab, so you need a platform that runs a Docker
Compose project (or a VPS with Docker). Notes:

- **VPS / self-managed Docker host** — works as-is. Run `./setup.sh`. Make sure
  `vm.max_map_count=262144` is set on the host (add it to `/etc/sysctl.conf` to
  persist). Open ports **443** (dashboard) and optionally **9200**.
- **Railway / Render / similar** — import the repo as a Docker Compose project.
  You must generate the certs **before** deploying (run step 2 of *Manual start*
  locally and commit `config/wazuh_indexer_ssl_certs/`, or run the generator as
  a pre-deploy job), because these platforms don't run `setup.sh` for you. Set
  `vm.max_map_count` via the platform's host settings if available; some managed
  hosts set it high enough already.
- **Memory** — if your host is tight on RAM, lower the indexer heap in
  `docker-compose.yml`:
  `OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m` (fine for this small dataset).
- **Single-container PaaS (one Dockerfile only)** — not supported by this
  template; Wazuh needs its three services. Ask for the all-in-one variant.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Indexer container exits / `max virtual memory areas` error | `sudo sysctl -w vm.max_map_count=262144` |
| Dashboard shows "no results" | Widen the time range to *Last 24 hours*; confirm the seeder finished (`docker compose logs wazuh.seeder`) |
| Seeder says "already seeded" but you want fresh data | See *Reset* above, or delete `soc-lab-seed-marker` (instructions in `docs/INSTRUCTOR_NOTES.md`) |
| Can't reach https://localhost | Check `docker compose ps`; the dashboard maps host **443** → container 5601 |
| Want a different Wazuh version | Edit the image tags in `docker-compose.yml` and the certs generator tag; keep all three in sync |

## Credits

Built on the official [wazuh/wazuh-docker](https://github.com/wazuh/wazuh-docker)
single-node deployment (v4.12.0). The web-attack dataset and training materials
are original to this lab.
