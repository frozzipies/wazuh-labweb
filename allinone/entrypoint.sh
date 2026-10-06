#!/usr/bin/env bash
# =============================================================================
#  SOC Lab entrypoint — indexer + dashboard + seeder. No manager, no filebeat.
#  Env vars:
#    ADMIN_PASSWORD  — dashboard login password (default: SecretPassword)
# =============================================================================
set -uo pipefail
log() { echo "[labweb $(date +%H:%M:%S)] $*"; }

ADMIN_PW="${ADMIN_PASSWORD:-SecretPassword}"
DEFAULT_PW="SecretPassword"

# Alias internal hostnames to loopback so cert SANs match.
if ! grep -q 'wazuh.indexer' /etc/hosts 2>/dev/null; then
  echo "127.0.0.1 wazuh.indexer wazuh.dashboard" >> /etc/hosts
fi

# If a custom password is set, regenerate the bcrypt hash before the indexer starts.
if [ "$ADMIN_PW" != "$DEFAULT_PW" ]; then
  log "custom ADMIN_PASSWORD detected, updating hash ..."
  HASH_SH="/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh"
  if [ -x "$HASH_SH" ] || chmod +x "$HASH_SH" 2>/dev/null; then
    NEW_HASH=$(OPENSEARCH_JAVA_HOME=/usr/share/wazuh-indexer/jdk \
      "$HASH_SH" -p "$ADMIN_PW" 2>/dev/null | grep '^\$2')
    if [ -n "$NEW_HASH" ]; then
      USERS_YML="/etc/wazuh-indexer/opensearch-security/internal_users.yml"
      NEW_HASH="$NEW_HASH" python3 -c "
import re, os
new_hash = os.environ['NEW_HASH']
path = '$USERS_YML'
with open(path) as f:
    content = f.read()
content = re.sub(
    r'(admin:\n\s+hash:\s*\x22)[^\x22]+(\x22)',
    r'\g<1>' + new_hash + r'\g<2>',
    content, count=1
)
with open(path, 'w') as f:
    f.write(content)
"
      chown wazuh-indexer:wazuh-indexer "$USERS_YML"
      chmod 640 "$USERS_YML"
      log "admin password hash updated."
    else
      log "WARN: hash.sh failed, falling back to default password."
      ADMIN_PW="$DEFAULT_PW"
    fi
  else
    log "WARN: hash.sh not found, falling back to default password."
    ADMIN_PW="$DEFAULT_PW"
  fi
fi

# Ensure ownership.
chown -R wazuh-indexer:wazuh-indexer /var/lib/wazuh-indexer /var/log/wazuh-indexer /etc/wazuh-indexer/certs 2>/dev/null || true
chmod 500 /etc/wazuh-indexer/certs 2>/dev/null || true
chmod 400 /etc/wazuh-indexer/certs/* 2>/dev/null || true

# Start the indexer with minimal heap.
log "starting wazuh-indexer ..."
runuser -u wazuh-indexer -- env \
  OPENSEARCH_PATH_CONF=/etc/wazuh-indexer \
  OPENSEARCH_JAVA_OPTS="${OPENSEARCH_JAVA_OPTS:--Xms1g -Xmx1g}" \
  /usr/share/wazuh-indexer/bin/opensearch > /var/log/wazuh-indexer/console.log 2>&1 &
IDX_PID=$!

# Wait for the indexer.
log "waiting for indexer ..."
up=0
for i in $(seq 1 60); do
  if curl -sk -u "admin:${ADMIN_PW}" https://wazuh.indexer:9200 >/dev/null 2>&1; then
    up=1; log "indexer is up."; break
  fi
  if ! kill -0 "$IDX_PID" 2>/dev/null; then
    log "ERROR: indexer died."; tail -n 40 /var/log/wazuh-indexer/console.log || true; exit 1
  fi
  sleep 5
done
[ "$up" = 1 ] || { log "ERROR: indexer timeout."; tail -n 40 /var/log/wazuh-indexer/console.log || true; exit 1; }

# Start the dashboard.
log "starting wazuh-dashboard ..."
runuser -u wazuh-dashboard -- env \
  OSD_PATH_CONF=/etc/wazuh-dashboard \
  /usr/share/wazuh-dashboard/bin/opensearch-dashboards > /var/log/wazuh-dashboard-console.log 2>&1 &

# Seed the training dataset.
log "seeding dataset ..."
INDEXER_URL="https://wazuh.indexer:9200" \
INDEXER_USERNAME="admin" INDEXER_PASSWORD="${ADMIN_PW}" WAIT_FOR_TEMPLATE="false" \
  python3 /opt/seeder/seed.py || log "seeder error (check above)."

log "========================================="
log " Ready. Dashboard: port 5601"
log " Login: admin / ${ADMIN_PW}"
log " Discover -> wazuh-alerts-* -> Last 24 hours"
log "========================================="

tail -n +1 -F /var/log/wazuh-indexer/console.log /var/log/wazuh-dashboard-console.log 2>/dev/null &
wait "$IDX_PID"
