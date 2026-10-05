#!/usr/bin/env bash
# =============================================================================
#  SOC Lab - Challenge 1 : one-command bootstrap
#  Brings up a Wazuh SIEM single-node stack pre-loaded with a web-attack
#  dataset for students to analyze.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

# --- pick the right compose command -----------------------------------------
if docker compose version >/dev/null 2>&1; then
  DC="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  DC="docker-compose"
else
  echo "ERROR: Docker Compose not found. Install Docker + the compose plugin." >&2
  exit 1
fi

# --- kernel requirement for the Wazuh indexer (OpenSearch) ------------------
NEED=262144
CUR=$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)
if [ "$CUR" -lt "$NEED" ]; then
  echo "[*] Raising vm.max_map_count ($CUR -> $NEED) for the indexer..."
  if ! sudo sysctl -w vm.max_map_count=$NEED 2>/dev/null; then
    echo "    WARNING: could not set vm.max_map_count. The indexer may fail to start."
    echo "    On the Docker host run:  sudo sysctl -w vm.max_map_count=262144"
  fi
fi

# --- generate TLS certificates (first run only) -----------------------------
if [ ! -f config/wazuh_indexer_ssl_certs/root-ca.pem ]; then
  echo "[*] Generating TLS certificates (first run)..."
  $DC -f generate-indexer-certs.yml run --rm generator
else
  echo "[=] Certificates already present - skipping generation."
fi

# --- launch the stack + seeder ----------------------------------------------
echo "[*] Building the seeder and starting the stack..."
$DC up -d --build

cat <<'EOF'

============================================================================
  Wazuh SOC training lab is starting.

  First boot takes ~2-4 minutes (indexer init + data seeding).

  Dashboard : https://localhost       (maps to container port 443)
  Login     : admin / SecretPassword

  Watch the dataset load:
      docker compose logs -f wazuh.seeder

  When the seeder prints "Done. NNN alerts loaded", open the dashboard,
  go to Discover (or Threat Hunting) and select index pattern
      wazuh-alerts-*
  then widen the time range to "Last 24 hours".

  Student brief : docs/STUDENT_BRIEF.md
  Answer key    : docs/INSTRUCTOR_NOTES.md
============================================================================
EOF
