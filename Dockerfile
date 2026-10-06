# =============================================================================
#  SOC Lab - Wazuh SIEM (indexer + dashboard + seeder) — NO manager/filebeat.
#  For PaaS platforms that only build one Dockerfile (ngelinx Application type).
#  Give it ~1.5 GB RAM.
# =============================================================================
FROM mirror.gcr.io/library/debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      curl gnupg apt-transport-https lsb-release adduser procps ca-certificates \
      python3 openssl \
 && printf '#!/bin/sh\ncase "$1" in\n  is-active|is-enabled|is-failed|status) exit 1 ;;\n  *) exit 0 ;;\nesac\n' > /usr/bin/systemctl \
 && chmod +x /usr/bin/systemctl \
 && printf '#!/bin/sh\nexit 0\n' > /usr/sbin/service && chmod +x /usr/sbin/service \
 && rm -rf /var/lib/apt/lists/*

# Wazuh APT repository.
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
      gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import \
 && chmod 644 /usr/share/keyrings/wazuh.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
      > /etc/apt/sources.list.d/wazuh.list

# Only indexer + dashboard. No manager, no filebeat.
RUN mkdir -p /etc/wazuh-indexer /etc/wazuh-dashboard \
 && apt-get update && apt-get install -y --no-install-recommends \
      wazuh-indexer=4.12.0-1 \
      wazuh-dashboard=4.12.0-1 \
 && rm -rf /var/lib/apt/lists/*

# ---- Certificates ----
COPY config/wazuh_indexer_ssl_certs/ /tmp/certs/
RUN set -e; \
    mkdir -p /etc/wazuh-indexer/certs /etc/wazuh-dashboard/certs; \
    cp /tmp/certs/root-ca.pem            /etc/wazuh-indexer/certs/root-ca.pem; \
    cp /tmp/certs/wazuh.indexer.pem      /etc/wazuh-indexer/certs/indexer.pem; \
    cp /tmp/certs/wazuh.indexer-key.pem  /etc/wazuh-indexer/certs/indexer-key.pem; \
    cp /tmp/certs/admin.pem              /etc/wazuh-indexer/certs/admin.pem; \
    cp /tmp/certs/admin-key.pem          /etc/wazuh-indexer/certs/admin-key.pem; \
    cp /tmp/certs/root-ca.pem            /etc/wazuh-dashboard/certs/root-ca.pem; \
    cp /tmp/certs/wazuh.dashboard.pem    /etc/wazuh-dashboard/certs/dashboard.pem; \
    cp /tmp/certs/wazuh.dashboard-key.pem /etc/wazuh-dashboard/certs/dashboard-key.pem; \
    rm -rf /tmp/certs; \
    chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs; \
    chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs; \
    chmod 500 /etc/wazuh-indexer/certs /etc/wazuh-dashboard/certs; \
    chmod 400 /etc/wazuh-indexer/certs/* /etc/wazuh-dashboard/certs/*

# ---- Configuration ----
COPY allinone/opensearch.yml                 /etc/wazuh-indexer/opensearch.yml
COPY config/wazuh_indexer/internal_users.yml /etc/wazuh-indexer/opensearch-security/internal_users.yml
COPY allinone/opensearch_dashboards.yml      /etc/wazuh-dashboard/opensearch_dashboards.yml
COPY allinone/wazuh.yml                       /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
RUN chown wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/opensearch-security/internal_users.yml \
 && chown -R wazuh-dashboard:wazuh-dashboard /usr/share/wazuh-dashboard/data/wazuh/config \
 && chmod 640 /etc/wazuh-indexer/opensearch-security/internal_users.yml

# ---- Seeder + entrypoint ----
COPY seeder/seed.py        /opt/seeder/seed.py
COPY allinone/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 5601
ENTRYPOINT ["/entrypoint.sh"]
