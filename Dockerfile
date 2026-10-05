# =============================================================================
#  SOC Lab - ALL-IN-ONE Wazuh SIEM (indexer + manager + dashboard + seeder)
#  in a single container, for PaaS platforms that build one Dockerfile per app
#  (ngelinx / Coolify / Dokploy "Application" type, Railway, etc.).
#
#  NOTE: Wazuh is officially a multi-container product. This all-in-one image is
#  convenient for single-container PaaS but is HEAVY: give it ~4 GB RAM.
#  For a VPS or any platform that runs Docker Compose, prefer docker-compose.yml
#  (lighter to operate, closer to a real deployment).
# =============================================================================
# Debian (glibc) base - required for Wazuh's .deb packages. Smaller than ubuntu,
# which also tends to pull more reliably. (Alpine is NOT usable: musl libc + apk
# are incompatible with Wazuh packages.)
FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

# Base tools. Stub out systemctl/service so the Wazuh .deb post-install scripts
# (which assume systemd) don't abort the build on this non-systemd base.
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl gnupg apt-transport-https lsb-release adduser procps ca-certificates \
      python3 openssl tar \
 && printf '#!/bin/sh\nexit 0\n' > /usr/bin/systemctl && chmod +x /usr/bin/systemctl \
 && printf '#!/bin/sh\nexit 0\n' > /usr/sbin/service   && chmod +x /usr/sbin/service \
 && rm -rf /var/lib/apt/lists/*

# Wazuh APT repository.
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
      gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import \
 && chmod 644 /usr/share/keyrings/wazuh.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
      > /etc/apt/sources.list.d/wazuh.list

# Install all three Wazuh components + Filebeat, pinned to 4.12.0.
RUN apt-get update && apt-get install -y --no-install-recommends \
      wazuh-indexer=4.12.0-1 \
      wazuh-manager=4.12.0-1 \
      filebeat=7.10.2-1 \
      wazuh-dashboard=4.12.0-1 \
 && rm -rf /var/lib/apt/lists/*

# Filebeat Wazuh module + alert template.
RUN curl -so /etc/filebeat/wazuh-template.json \
      https://raw.githubusercontent.com/wazuh/wazuh/v4.12.0/extensions/elasticsearch/7.x/wazuh-template.json \
 && chmod go+r /etc/filebeat/wazuh-template.json \
 && curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.4.tar.gz \
      | tar -xvz -C /usr/share/filebeat/module

# ---- Certificates (reuse the committed lab certs, renamed per component) ----
COPY config/wazuh_indexer_ssl_certs/ /tmp/certs/
RUN set -e; \
    mkdir -p /etc/wazuh-indexer/certs /etc/filebeat/certs /etc/wazuh-dashboard/certs; \
    cp /tmp/certs/root-ca.pem            /etc/wazuh-indexer/certs/root-ca.pem; \
    cp /tmp/certs/wazuh.indexer.pem      /etc/wazuh-indexer/certs/indexer.pem; \
    cp /tmp/certs/wazuh.indexer-key.pem  /etc/wazuh-indexer/certs/indexer-key.pem; \
    cp /tmp/certs/admin.pem              /etc/wazuh-indexer/certs/admin.pem; \
    cp /tmp/certs/admin-key.pem          /etc/wazuh-indexer/certs/admin-key.pem; \
    cp /tmp/certs/root-ca.pem            /etc/filebeat/certs/root-ca.pem; \
    cp /tmp/certs/wazuh.manager.pem      /etc/filebeat/certs/filebeat.pem; \
    cp /tmp/certs/wazuh.manager-key.pem  /etc/filebeat/certs/filebeat-key.pem; \
    cp /tmp/certs/root-ca.pem            /etc/wazuh-dashboard/certs/root-ca.pem; \
    cp /tmp/certs/wazuh.dashboard.pem    /etc/wazuh-dashboard/certs/dashboard.pem; \
    cp /tmp/certs/wazuh.dashboard-key.pem /etc/wazuh-dashboard/certs/dashboard-key.pem; \
    rm -rf /tmp/certs; \
    chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs; \
    chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs; \
    chmod 500 /etc/wazuh-indexer/certs /etc/wazuh-dashboard/certs /etc/filebeat/certs; \
    chmod 400 /etc/wazuh-indexer/certs/* /etc/wazuh-dashboard/certs/* /etc/filebeat/certs/*

# ---- Component configuration ----
COPY allinone/opensearch.yml                 /etc/wazuh-indexer/opensearch.yml
COPY config/wazuh_indexer/internal_users.yml /etc/wazuh-indexer/opensearch-security/internal_users.yml
COPY allinone/opensearch_dashboards.yml      /etc/wazuh-dashboard/opensearch_dashboards.yml
COPY allinone/wazuh.yml                       /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
COPY allinone/filebeat.yml                    /etc/filebeat/filebeat.yml
RUN chown wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/opensearch-security/internal_users.yml \
 && chown -R wazuh-dashboard:wazuh-dashboard /usr/share/wazuh-dashboard/data/wazuh/config \
 && chmod 640 /etc/wazuh-indexer/opensearch-security/internal_users.yml

# ---- Filebeat keystore (admin / SecretPassword) ----
RUN filebeat keystore create --path.config /etc/filebeat --path.data /var/lib/filebeat --force \
 && printf 'admin'          | filebeat keystore add username --stdin --force --path.config /etc/filebeat --path.data /var/lib/filebeat \
 && printf 'SecretPassword' | filebeat keystore add password --stdin --force --path.config /etc/filebeat --path.data /var/lib/filebeat

# ---- Seeder + entrypoint ----
COPY seeder/seed.py        /opt/seeder/seed.py
COPY allinone/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 5601
ENTRYPOINT ["/entrypoint.sh"]
