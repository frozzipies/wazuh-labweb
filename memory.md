# AI Generation Template — Wazuh SOC Lab

Use this document as a reference/prompt when asking an AI to generate or
customize this project. It captures every architectural decision, file layout,
and configuration detail so the result is reproducible.

---

## What this project is

A **single-container, zero-config Wazuh SIEM training lab** that:

1. Boots the real Wazuh 4.12.0 stack (indexer + dashboard, no manager/filebeat)
2. Auto-seeds a realistic web-attack dataset (~278 alerts, last 24 hours)
3. Students log in and start hunting immediately — no setup needed

**Target audience:** SOC/security training, CTF challenges, classroom demos.

---

## Architecture

```
┌─────────────────────────────────────────┐
│           Single Docker Container       │
│                                         │
│  ┌─────────────┐  ┌──────────────────┐  │
│  │ Wazuh       │  │ Wazuh Dashboard  │  │
│  │ Indexer     │──│ (port 5601)      │  │
│  │ (OpenSearch)│  │ HTTPS or HTTP    │  │
│  └─────────────┘  └──────────────────┘  │
│         │                               │
│  ┌──────┴──────┐                        │
│  │ Seeder      │  (one-shot, then idle) │
│  │ (Python)    │                        │
│  └─────────────┘                        │
└─────────────────────────────────────────┘
```

- **Indexer** = Wazuh's bundled OpenSearch (stores alerts)
- **Dashboard** = Wazuh's UI (Discover page for querying)
- **Seeder** = Python script that bulk-loads alerts via the OpenSearch `_bulk` API

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `ADMIN_PASSWORD` | `SecretPassword` | Dashboard login password (username is always `admin`) |
| `OPENSEARCH_JAVA_OPTS` | `-Xms1g -Xmx1g` | Indexer JVM heap size |

Set these in PaaS dashboards (e.g., ngelinx Environment Variables) or in
`docker-compose.yml` under `environment:`.

---

## File Layout

```
.
├── Dockerfile                          # All-in-one: indexer + dashboard + seeder
├── docker-compose.yml                  # Multi-container (local dev)
├── docker-compose.override.yml         # Adds the seeder service
├── setup.sh                            # Quick start (sets vm.max_map_count + docker compose up)
├── allinone/
│   ├── entrypoint.sh                   # Container startup: start indexer → wait → start dashboard → seed
│   ├── opensearch.yml                  # Indexer config (single-node, TLS, certs)
│   ├── opensearch_dashboards.yml       # Dashboard config (connects to indexer via HTTPS internally)
│   └── wazuh.yml                       # Wazuh plugin API config (points to manager, non-functional)
├── config/
│   ├── wazuh_indexer/
│   │   └── internal_users.yml          # OpenSearch security users (admin bcrypt hash lives here)
│   └── wazuh_indexer_ssl_certs/        # TLS certificates (pre-generated, self-signed)
│       ├── root-ca.pem / root-ca-key.pem
│       ├── admin.pem / admin-key.pem
│       ├── wazuh.indexer.pem / wazuh.indexer-key.pem
│       └── wazuh.dashboard.pem / wazuh.dashboard-key.pem
├── seeder/
│   ├── Dockerfile                      # Python 3.11-slim image for the seeder
│   └── seed.py                         # Generates alerts and bulk-indexes them
├── docs/
│   ├── STUDENT_BRIEF.md                # Student-facing exercise instructions
│   └── INSTRUCTOR_NOTES.md             # Answer key
└── README.md
```

---

## How the Entrypoint Works (`allinone/entrypoint.sh`)

1. **Reads `ADMIN_PASSWORD`** env var (default: `SecretPassword`)
2. If custom password → runs bundled `hash.sh` to generate bcrypt hash → patches
   `internal_users.yml` with the new hash before the indexer starts
3. Adds `/etc/hosts` aliases (`wazuh.indexer`, `wazuh.dashboard` → `127.0.0.1`)
   so TLS certificate SANs match
4. Starts the **indexer** (`wazuh-indexer` user, configurable heap)
5. Waits for indexer to respond on `https://wazuh.indexer:9200`
6. Starts the **dashboard** (`wazuh-dashboard` user, port 5601)
7. Runs the **seeder** (Python) — indexes alerts, then exits
8. Tails logs from both services

---

## How the Seeder Works (`seeder/seed.py`)

1. Waits for indexer at `INDEXER_URL` (default: `https://wazuh.indexer:9200`)
2. Checks if already seeded (marker doc in `soc-lab-seed-marker` index)
3. Creates index template for `wazuh-alerts-*` with proper field mappings
4. Generates ~278 web-attack alerts spread over 24 hours:
   - **Phase 1 (recon):** forced browsing, directory scanning
   - **Phase 2 (exploitation):** path traversal, SQL injection, XSS
   - **Phase 3 (post-exploit):** web shell upload and command execution
5. Bulk-indexes via `POST /_bulk` with NDJSON
6. Marks as seeded so restarts don't duplicate data

**Auth:** uses `INDEXER_USERNAME` / `INDEXER_PASSWORD` env vars, TLS verification
disabled (`ssl._create_unverified_context`).

---

## Key Configurations

### `allinone/opensearch_dashboards.yml`

```yaml
server.host: 0.0.0.0
server.port: 5601
opensearch.hosts: https://wazuh.indexer:9200      # Internal HTTPS
opensearch.username: kibanaserver                   # Internal service account
opensearch.password: kibanaserver                   # (not the admin login)
server.ssl.enabled: false                           # HTTP externally (PaaS terminates TLS)
uiSettings.overrides.defaultRoute: /app/discover    # Land on Discover page
```

### `config/wazuh_indexer/internal_users.yml`

- `admin` — bcrypt-hashed password, `reserved: true`, backend role `admin`
- `kibanaserver` — internal service account for dashboard→indexer connection
- Other demo users (kibanaro, logstash, readall, snapshotrestore) — unused

### Security (TLS)

- Indexer ↔ Dashboard: HTTPS with self-signed certs (internal only)
- Dashboard → outside: HTTP (PaaS reverse proxy handles public TLS)
- Certs pre-generated in `config/wazuh_indexer_ssl_certs/`

---

## Deploying on ngelinx PaaS

1. **New service → GitHub Repo**
2. **Link repositori:** `https://github.com/frozzipies/wazuh-labweb`
3. **Branch:** `main`
4. **Port aplikasi:** `5601`
5. **Environment Variables:**
   - `ADMIN_PASSWORD` = `YourPassword`
6. **Backend protocol:** HTTP (dashboard serves HTTP, PaaS terminates TLS)
7. **RAM:** ~1.5 GB minimum

---

## Customization Guide

### Change the attack scenario

Edit `seeder/seed.py`:
- Modify the alert templates (rule IDs, descriptions, MITRE tactics)
- Add/remove attack phases
- Change the number of alerts (`count` parameter)

### Add more agents

In `seed.py`, add entries to the agent list with different names/IPs.
The Wazuh dashboard will show them in the Agents breakdown.

### Change the default landing page

In `allinone/opensearch_dashboards.yml`, change `uiSettings.overrides.defaultRoute`:
- `/app/discover` — Discover page (current)
- `/app/wazuh` — Wazuh Security Events (requires working manager)

### Reduce memory usage

Set `OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m` (minimum ~512 MB heap for indexer).

---

## AI Prompt Template

Use this prompt to ask an AI to generate a similar lab:

```
Create a Dockerized SIEM training lab with these specs:
- Stack: [Wazuh / OpenSearch / ELK / Splunk]
- Attack scenario: [web attacks / brute force / malware / insider threat]
- Number of alerts: [100-5000]
- MITRE ATT&CK tactics: [list tactics]
- Agents/hosts: [list hostnames and OS types]
- Authentication: configurable via ADMIN_PASSWORD env var
- Deploy target: single Dockerfile for PaaS (port 5601, HTTP backend)
- Auto-seed on first boot, skip if already seeded
- Include student brief and instructor answer key

Use this repo as a reference for the architecture:
https://github.com/frozzipies/wazuh-labweb
See memory.md for the full file layout, entrypoint flow, and seeder logic.
```

---

## Tech Stack Versions

| Component | Version |
|---|---|
| Wazuh Indexer | 4.12.0 (based on OpenSearch 2.x) |
| Wazuh Dashboard | 4.12.0 (based on OpenSearch Dashboards) |
| Base image | Debian 12 slim |
| Python (seeder) | 3.11 (system python in Debian) |
| TLS | Self-signed (generated via `generate-indexer-certs.yml`) |
