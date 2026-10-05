# Challenge 1 — Web Server Under Attack 🕵️

## Scenario

You are the SOC analyst on shift. Over the **last 24 hours**, alerts have been
piling up from a public-facing nginx web server, **`web-server-01`**
(internal IP `10.0.0.50`). Management wants to know: *was it just noise, or did
someone actually break in?*

All the evidence is in Wazuh. Your job is to reconstruct what happened.

## Getting in

| | |
|---|---|
| **Dashboard** | the URL your instructor gives you (local: https://localhost:5601) — accept the self-signed certificate warning |
| **Username** | `admin` |
| **Password** | `SecretPassword` |

1. Log in to the Wazuh dashboard.
2. Open **Discover** (menu ☰ → *Discover*), or **Threat Hunting** under the
   Security section.
3. Select the index pattern **`wazuh-alerts-*`**.
4. Set the time picker (top right) to **Last 24 hours**.

You should see a few hundred alerts. Start hunting.

## Your mission

Answer these questions using only what you can find in Wazuh. Write down the
**evidence** (the specific alerts / fields) that backs each answer.

1. **Triage** — How many distinct source IPs generated alerts? Which ones look
   hostile vs. benign? (Hint: filter on `data.srcip`.)
2. **Attribution** — Which single IP is responsible for the bulk of the
   malicious activity? Where (geographically) does it claim to come from?
3. **Timeline** — Reconstruct the attacker's actions in order. What did they do
   **first**, and how did the activity **escalate** over time?
4. **Techniques** — Identify each attack technique used against the server.
   Map at least three of them to **MITRE ATT&CK** (the alerts carry
   `rule.mitre.*` fields).
5. **The big question** — Did the attacker *succeed*? Find the moment the
   server went from *rejecting* the attacker to *serving* them. What is the
   single most severe alert, and what does it tell you?
6. **Red herring** — One noisy IP looks scary but never actually achieved
   anything. Which one, and how can you tell it apart from the real threat?

## Useful fields & filters

| Field | What it is |
|---|---|
| `data.srcip` | Source IP of the request |
| `data.url` | The requested URL (payloads live here!) |
| `data.id` | HTTP status code (`404` = blocked/not found, `200` = **served**) |
| `rule.id` / `rule.level` | Wazuh rule and severity (higher = worse) |
| `rule.description` | Human-readable detection |
| `rule.mitre.id` | MITRE ATT&CK technique ID |
| `full_log` | The raw nginx access-log line |

Try these searches in Discover:

```
rule.level >= 10
data.srcip : "203.0.113.77"
rule.groups : "sql_injection"
data.id : "200" and data.srcip : "203.0.113.77"
```

## Deliverable

A short incident summary (½–1 page): what happened, the kill-chain timeline,
MITRE techniques, whether the box was compromised, and one recommendation to
prevent it. Good luck. 🚀
