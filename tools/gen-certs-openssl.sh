#!/usr/bin/env bash
# =============================================================================
#  Offline TLS certificate generator for the Wazuh single-node lab.
#
#  Produces the exact filenames / subject DNs / SANs / key format that the
#  Wazuh indexer security plugin, filebeat, and dashboard expect - WITHOUT
#  needing to pull the wazuh-certs-generator Docker image. Pure openssl.
#
#  Subjects are written C..CN so their RFC2253 rendering (reverse order) is
#  "CN=<node>,OU=Wazuh,O=Wazuh,L=California,C=US" - matching nodes_dn/admin_dn
#  in config/wazuh_indexer/wazuh.indexer.yml. Keys are emitted as PKCS#8
#  (-----BEGIN PRIVATE KEY-----), which OpenSearch requires.
#
#  Re-run any time to rotate certs:  bash tools/gen-certs-openssl.sh
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="config/wazuh_indexer_ssl_certs"
mkdir -p "$OUT"
cd "$OUT"

DAYS=3650
SUBJ_BASE="/C=US/L=California/O=Wazuh/OU=Wazuh"

echo "[*] Generating Root CA..."
openssl genrsa -out root-ca.key 2048 2>/dev/null
openssl req -x509 -new -nodes -key root-ca.key -sha256 -days $DAYS \
  -subj "${SUBJ_BASE}/CN=root-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out root-ca.pem 2>/dev/null

# gen_cert <name> <CN> <san-dns-or-empty>
gen_cert() {
  local name="$1" cn="$2" san="${3:-}"
  echo "[*] Generating certificate: ${name} (CN=${cn})"
  openssl genrsa -out "${name}-key-pkcs1.tmp" 2048 2>/dev/null
  # OpenSearch needs PKCS#8 keys
  openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt \
    -in "${name}-key-pkcs1.tmp" -out "${name}-key.pem" 2>/dev/null
  rm -f "${name}-key-pkcs1.tmp"

  local ext="basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth"
  if [ -n "$san" ]; then
    ext="${ext}
subjectAltName=DNS:${san}"
  fi
  printf '%s\n' "$ext" > "${name}.exttmp"

  openssl req -new -key "${name}-key.pem" \
    -subj "${SUBJ_BASE}/CN=${cn}" -out "${name}.csrtmp" 2>/dev/null
  openssl x509 -req -in "${name}.csrtmp" -CA root-ca.pem -CAkey root-ca.key \
    -CAcreateserial -sha256 -days $DAYS \
    -extfile "${name}.exttmp" -out "${name}.pem" 2>/dev/null
  rm -f "${name}.csrtmp" "${name}.exttmp"
}

# Transport/admin certs (DN must match wazuh.indexer.yml). SAN only needed where
# a client verifies hostname (filebeat -> indexer uses verification_mode=full).
gen_cert "wazuh.indexer"   "wazuh.indexer"   "wazuh.indexer"
gen_cert "admin"           "admin"           ""
gen_cert "wazuh.manager"   "wazuh.manager"   "wazuh.manager"
gen_cert "wazuh.dashboard" "wazuh.dashboard" "wazuh.dashboard"

# The manager container mounts the CA as root-ca-manager.pem
cp -f root-ca.pem root-ca-manager.pem

rm -f root-ca.srl
echo
echo "[+] Done. Files in ${OUT}:"
ls -1
