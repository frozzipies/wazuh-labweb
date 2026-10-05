#!/usr/bin/env bash
# =============================================================================
#  All-in-one Wazuh SOC lab - container entrypoint.
#  Starts indexer -> (manager, filebeat) -> dashboard, then seeds the dataset.
#  Components other than the indexer are best-effort: even if the manager/API
#  don't come up, the dashboard's Discover view works on the seeded data.
# =============================================================================
set -uo pipefail
log() { echo "[allinone $(date +%H:%M:%S)] $*"; }

ADMIN_PW="${INDEXER_PASSWORD:-SecretPassword}"

# 1. Alias the internal hostnames to loopback so cert SANs still match.
if ! grep -q 'wazuh.indexer' /etc/hosts 2>/dev/null; then
  echo "127.0.0.1 wazuh.indexer wazuh.manager wazuh.dashboard" >> /etc/hosts
fi

# 2. Ensure ownership/permissions (covers the case of a mounted data volume).
chown -R wazuh-indexer:wazuh-indexer /var/lib/wazuh-indexer /var/log/wazuh-indexer /etc/wazuh-indexer/certs 2>/dev/null || true
chmod 500 /etc/wazuh-indexer/certs 2>/dev/null || true
chmod 400 /etc/wazuh-indexer/certs/* 2>/dev/null || true

# 3. Start the Wazuh indexer (OpenSearch) as its own user.
log "starting wazuh-indexer ..."
runuser -u wazuh-indexer -- env \
  OPENSEARCH_PATH_CONF=/etc/wazuh-indexer \
  OPENSEARCH_JAVA_OPTS="${OPENSEARCH_JAVA_OPTS:--Xms1g -Xmx1g}" \
  /usr/share/wazuh-indexer/bin/opensearch > /var/log/wazuh-indexer/console.log 2>&1 &
IDX_PID=$!

# 4. Wait for the indexer HTTP API.
log "waiting for the indexer to accept requests (up to ~5 min) ..."
up=0
for i in $(seq 1 60); do
  if curl -sk -u "admin:${ADMIN_PW}" https://wazuh.indexer:9200 >/dev/null 2>&1; then
    up=1; log "indexer is up."; break
  fi
  if ! kill -0 "$IDX_PID" 2>/dev/null; then
    log "ERROR: indexer process died. Last log lines:"; tail -n 40 /var/log/wazuh-indexer/console.log || true
    exit 1
  fi
  sleep 5
done
[ "$up" = 1 ] || { log "ERROR: indexer never became ready."; tail -n 40 /var/log/wazuh-indexer/console.log || true; exit 1; }

# 5. Load the Wazuh alert template (idempotent) so seeded alerts map correctly
#    even if filebeat never runs.
log "applying wazuh index template ..."
curl -sk -u "admin:${ADMIN_PW}" -XPUT "https://wazuh.indexer:9200/_template/wazuh" \
  -H 'Content-Type: application/json' --data-binary @/etc/filebeat/wazuh-template.json >/dev/null 2>&1 \
  && log "template applied." || log "template apply skipped/failed (dynamic mapping will be used)."

# 6. Start the Wazuh manager (best effort).
log "starting wazuh-manager ..."
/var/ossec/bin/wazuh-control start >/var/log/wazuh-manager-start.log 2>&1 || log "manager start returned non-zero (continuing)."

# 7. Start Filebeat (best effort) - ships future manager alerts to the indexer.
log "starting filebeat ..."
/usr/share/filebeat/bin/filebeat -e \
  -c /etc/filebeat/filebeat.yml \
  --path.home /usr/share/filebeat --path.config /etc/filebeat \
  --path.data /var/lib/filebeat --path.logs /var/log/filebeat \
  > /var/log/filebeat/console.log 2>&1 &

# 8. Start the Wazuh dashboard.
log "starting wazuh-dashboard (first boot optimizes assets, ~1-2 min) ..."
runuser -u wazuh-dashboard -- env \
  OSD_PATH_CONF=/etc/wazuh-dashboard \
  /usr/share/wazuh-dashboard/bin/opensearch-dashboards > /var/log/wazuh-dashboard-console.log 2>&1 &
DASH_PID=$!

# 9. Seed the training dataset (template already present -> no need to wait).
log "seeding the web-attack dataset ..."
INDEXER_URL="https://wazuh.indexer:9200" \
INDEXER_USERNAME="admin" INDEXER_PASSWORD="${ADMIN_PW}" WAIT_FOR_TEMPLATE="false" \
  python3 /opt/seeder/seed.py || log "seeder reported an error (check logs above)."

log "=========================================================================="
log " Wazuh all-in-one is up. Dashboard: https://<host>:5601  (admin / ${ADMIN_PW})"
log " Discover -> index pattern wazuh-alerts-* -> Last 24 hours."
log "=========================================================================="

# 10. Keep the container alive, tailing the most useful logs.
tail -n +1 -F /var/log/wazuh-indexer/console.log /var/log/wazuh-dashboard-console.log \
  /var/log/filebeat/console.log 2>/dev/null &
wait "$IDX_PID"
