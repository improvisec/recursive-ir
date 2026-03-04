# ------------------------------------------------------------------
# Recursive-IR install script
# Copyright (c) 2026 Mark Jayson Alvarez
# Licensed under the Recursive-IR License
# ------------------------------------------------------------------
# #!/usr/bin/env bash
set -euo pipefail
trap 'echo "❌ install_opensearch_stack.sh failed at line $LINENO"; exit 1' ERR

# ------------------------------------------------------------------
# Recursive-IR Full Stack Installer (APT-only)
# OpenSearch + OpenSearch Dashboards + Logstash + Filebeat
#
# Fresh-install focused:
# - No idempotency, no migration logic
# - Single-node + loopback only (127.0.0.1)
# - Non-interactive TLS generation (self-signed CA)
# - Does NOT modify /etc/recursive-ir/conf/recursive.env
#   (dfir init --bootstrap-env should create it from recursive.env.sample)
# - Prints installed versions + service statuses + verification results at end
# ------------------------------------------------------------------

# =========================
# Settings (override via env)
# =========================
OS_APT_MAJOR="${OS_APT_MAJOR:-3.x}"            # OpenSearch APT "3.x" track
ELASTIC_APT_MAJOR="${ELASTIC_APT_MAJOR:-8.x}" # Elastic APT track for logstash/filebeat packages

OS_PASS="${OS_PASS:-}"

# Canonical cert location (your choice)
RI_ETC_BASE="/etc/recursive-ir"
RI_CERTS_OS="${RI_ETC_BASE}/certs/opensearch"
RI_CA="${RI_CERTS_OS}/root-ca.pem"
RI_CA_KEY="${RI_CERTS_OS}/root-ca-key.pem"
RI_NODE_CERT="${RI_CERTS_OS}/node.pem"
RI_NODE_KEY="${RI_CERTS_OS}/node-key.pem"
RI_ADMIN_CERT="${RI_CERTS_OS}/admin.pem"
RI_ADMIN_KEY="${RI_CERTS_OS}/admin-key.pem"

# Your shipped config locations
RI_CONF_ENV="${RI_ETC_BASE}/conf/recursive.env"
RI_LOGSTASH_ETC="${RI_ETC_BASE}/logstash"
RI_FILEBEAT_ETC="${RI_ETC_BASE}/filebeat"

OS_URL_LOCAL="https://127.0.0.1:9200"

# =========================
# Helpers
# =========================
need_root() { [[ ${EUID:-0} -eq 0 ]] || { echo "Run as root (sudo)."; exit 1; }; }
section() { echo; echo "==> $*"; }
require_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "Missing command: $1"; exit 1; }; }
dpkg_ver() { dpkg -s "$1" 2>/dev/null | awk -F': ' '/^Version:/{print $2}'; }

# =========================
# Pre-flight
# =========================
need_root
export DEBIAN_FRONTEND=noninteractive

if [[ -z "${OS_PASS}" ]]; then
  echo "ERROR: Set OS_PASS (required for OpenSearch fresh installs)."
  echo "Example:"
  echo "  sudo OS_PASS='StrongPassHere' $0"
  exit 1
fi

section "Install base dependencies (fresh Ubuntu safe)"
apt-get update
apt-get install -y \
  openssl curl gnupg2 lsb-release ca-certificates apt-transport-https \
  tar wget

require_cmd systemctl
require_cmd curl
require_cmd gpg
require_cmd openssl
require_cmd dpkg

mkdir -p /etc/apt/keyrings

# =========================
# Add OpenSearch APT repo + install
# =========================
section "Add OpenSearch APT repo and install OpenSearch + Dashboards"
curl -fsSL https://artifacts.opensearch.org/publickeys/opensearch-release.pgp \
  | gpg --dearmor -o /etc/apt/keyrings/opensearch.gpg

cat > /etc/apt/sources.list.d/opensearch.list <<EOF
deb [signed-by=/etc/apt/keyrings/opensearch.gpg] https://artifacts.opensearch.org/releases/bundle/opensearch/${OS_APT_MAJOR}/apt stable main
EOF

# Tolerate releaseinfo change if needed
if ! apt-get update; then
  apt-get update --allow-releaseinfo-change
fi

env OS_PASS="${OS_PASS}" \
  apt-get install -y opensearch opensearch-dashboards

systemctl enable opensearch opensearch-dashboards

# =========================
# Add Elastic APT repo + install Logstash + Filebeat
# =========================
section "Add Elastic APT repo and install Logstash + Filebeat (APT)"
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch \
  | gpg --dearmor -o /etc/apt/keyrings/elastic.gpg

cat > /etc/apt/sources.list.d/elastic.list <<EOF
deb [signed-by=/etc/apt/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/${ELASTIC_APT_MAJOR}/apt stable main
EOF

apt-get update
apt-get install -y logstash filebeat

# Stop vendor units; we'll run with Recursive-IR config + our own systemd units.
systemctl stop logstash 2>/dev/null || true
systemctl stop filebeat 2>/dev/null || true
systemctl disable logstash 2>/dev/null || true
systemctl disable filebeat 2>/dev/null || true

# =========================
# Generate TLS certs (non-interactive)
# =========================
section "Generate OpenSearch TLS (self-signed CA) under ${RI_CERTS_OS}"
mkdir -p "${RI_CERTS_OS}"
chmod 700 "${RI_CERTS_OS}"

# Root CA
openssl genrsa -out "${RI_CA_KEY}" 2048
openssl req -new -x509 -sha256 \
  -key "${RI_CA_KEY}" \
  -subj "/CN=recursive-ir-root-ca" \
  -out "${RI_CA}" -days 730

# Admin cert (CN must match plugins.security.authcz.admin_dn below)
openssl genrsa -out "${RI_ADMIN_KEY}" 2048
openssl req -new -key "${RI_ADMIN_KEY}" -subj "/CN=ri-admin" -out "${RI_CERTS_OS}/admin.csr"
openssl x509 -req -in "${RI_CERTS_OS}/admin.csr" \
  -CA "${RI_CA}" -CAkey "${RI_CA_KEY}" -CAcreateserial \
  -out "${RI_ADMIN_CERT}" -days 730 -sha256
rm -f "${RI_CERTS_OS}/admin.csr"

# Node cert with SAN for localhost + 127.0.0.1 (works with loopback-only)
openssl genrsa -out "${RI_NODE_KEY}" 2048
cat > "${RI_CERTS_OS}/node.cnf" <<EOF
[req]
prompt = no
distinguished_name = dn
req_extensions = req_ext

[dn]
CN = ri-node

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

openssl req -new -key "${RI_NODE_KEY}" -out "${RI_CERTS_OS}/node.csr" -config "${RI_CERTS_OS}/node.cnf"
openssl x509 -req -in "${RI_CERTS_OS}/node.csr" \
  -CA "${RI_CA}" -CAkey "${RI_CA_KEY}" -CAcreateserial \
  -out "${RI_NODE_CERT}" -days 730 -sha256 \
  -extensions req_ext -extfile "${RI_CERTS_OS}/node.cnf"
rm -f "${RI_CERTS_OS}/node.csr" "${RI_CERTS_OS}/node.cnf"

# Permissions: CA/world-readable is fine; keys restricted
chmod 644 "${RI_CA}" "${RI_NODE_CERT}" "${RI_ADMIN_CERT}"
chmod 600 "${RI_CA_KEY}" "${RI_NODE_KEY}" "${RI_ADMIN_KEY}"

# =========================
# Configure OpenSearch (single-node, loopback, TLS)
# =========================
section "Configure /etc/opensearch/opensearch.yml (single-node, loopback, TLS)"

# Ensure loopback + single-node are explicitly set
if ! grep -qE '^[[:space:]]*network\.host:' /etc/opensearch/opensearch.yml; then
  echo "network.host: 127.0.0.1" >> /etc/opensearch/opensearch.yml
else
  sed -ri 's@^[[:space:]]*network\.host:.*@network.host: 127.0.0.1@g' /etc/opensearch/opensearch.yml
fi

if ! grep -qE '^[[:space:]]*discovery\.type:' /etc/opensearch/opensearch.yml; then
  echo "discovery.type: single-node" >> /etc/opensearch/opensearch.yml
else
  sed -ri 's@^[[:space:]]*discovery\.type:.*@discovery.type: single-node@g' /etc/opensearch/opensearch.yml
fi

# Append our security TLS block (avoid duplicating if already present)
if ! grep -q "Recursive-IR TLS block" /etc/opensearch/opensearch.yml; then
  cat >> /etc/opensearch/opensearch.yml <<EOF

######## Recursive-IR TLS block (managed by installer) ########
plugins.security.ssl.transport.pemcert_filepath: ${RI_NODE_CERT}
plugins.security.ssl.transport.pemkey_filepath: ${RI_NODE_KEY}
plugins.security.ssl.transport.pemtrustedcas_filepath: ${RI_CA}

plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: ${RI_NODE_CERT}
plugins.security.ssl.http.pemkey_filepath: ${RI_NODE_KEY}
plugins.security.ssl.http.pemtrustedcas_filepath: ${RI_CA}

plugins.security.allow_default_init_securityindex: true
plugins.security.authcz.admin_dn:
  - 'CN=ri-admin'
plugins.security.nodes_dn:
  - 'CN=ri-node'
plugins.security.audit.type: internal_opensearch
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.restapi.roles_enabled: ["all_access", "security_rest_api_access"]
######## End Recursive-IR TLS block ########
EOF
fi

systemctl restart opensearch

# =========================
# Apply security config using securityadmin.sh
# =========================
section "Apply OpenSearch security config (securityadmin.sh)"
OS_SEC_TOOLS="/usr/share/opensearch/plugins/opensearch-security/tools/securityadmin.sh"
if [[ ! -x "${OS_SEC_TOOLS}" ]]; then
  echo "Expected securityadmin.sh not found at: ${OS_SEC_TOOLS}"
  exit 1
fi

"${OS_SEC_TOOLS}" \
  -cd /etc/opensearch/opensearch-security/ \
  -cacert "${RI_CA}" \
  -cert "${RI_ADMIN_CERT}" \
  -key "${RI_ADMIN_KEY}" \
  -icl -nhnv

# =========================
# Configure Dashboards to trust our CA (loopback)
# =========================
section "Configure OpenSearch Dashboards to use ${OS_URL_LOCAL} + CA"
DASH_YML="/etc/opensearch-dashboards/opensearch_dashboards.yml"

if ! grep -q "Recursive-IR Dashboards block" "${DASH_YML}"; then
  cat >> "${DASH_YML}" <<EOF

######## Recursive-IR Dashboards block (managed by installer) ########
opensearch.hosts: ["${OS_URL_LOCAL}"]
opensearch.username: "admin"
opensearch.password: "${OS_PASS}"
opensearch.ssl.certificateAuthorities: ["${RI_CA}"]
######## End Recursive-IR Dashboards block ########
EOF
fi

# =========================
# Install Recursive-IR branding assets into OpenSearch Dashboards (local /ui/assets)
# =========================
section "Install Recursive-IR branding assets (Dashboards /ui/assets)"

# Source images (prefer installer-synced assets, fallback to repo path)
SRC_IMAGES=""
if [[ -d "${RI_ETC_BASE:-/etc/recursive-ir}/assets/images" ]]; then
  SRC_IMAGES="${RI_ETC_BASE:-/etc/recursive-ir}/assets/images"
elif [[ -d "${RI_REPO_ROOT:-}/web/docker/ui/recursive-ir/public/assets/images" ]]; then
  SRC_IMAGES="${RI_REPO_ROOT}/web/docker/ui/recursive-ir/public/assets/images"
fi

if [[ -z "${SRC_IMAGES}" ]]; then
  echo "[branding] ERROR: could not find branding source images."
  echo "  expected either:"
  echo "    - /etc/recursive-ir/assets/images"
  echo "    - <repo>/web/docker/ui/recursive-ir/public/assets/images"
  exit 1
fi

# Find Dashboards "ui/assets" directory (served at /ui/assets)
OSD_HOME="/usr/share/opensearch-dashboards"
ASSETS_DIR=""
for d in \
  "${OSD_HOME}/src/core/server/core_app/assets" \
  "${OSD_HOME}/core/server/core_app/assets" \
  "${OSD_HOME}/ui/assets" \
  "${OSD_HOME}/assets" \
; do
  if [[ -d "$d" ]]; then
    ASSETS_DIR="$d"
    break
  fi
done

if [[ -z "${ASSETS_DIR}" ]]; then
  echo "[branding] ERROR: could not find Dashboards assets dir under ${OSD_HOME}"
  exit 1
fi

mkdir -p "${ASSETS_DIR}/images"

# Copy branding images
install -m 0644 "${SRC_IMAGES}/recursive-ir-banner.png"        "${ASSETS_DIR}/images/"
install -m 0644 "${SRC_IMAGES}/recursive-ir-banner-light.png"  "${ASSETS_DIR}/images/"
install -m 0644 "${SRC_IMAGES}/recursive-ir-logo-dark.png"     "${ASSETS_DIR}/images/"
install -m 0644 "${SRC_IMAGES}/recursive-ir-logo-light.png"    "${ASSETS_DIR}/images/"
install -m 0644 "${SRC_IMAGES}/recursive-ir-spinner-light.gif" "${ASSETS_DIR}/images/"

echo "[branding] Installed images into: ${ASSETS_DIR}/images"
ls -la "${ASSETS_DIR}/images" | sed -n '1,120p'

# =========================
# Configure Dashboards branding to use local /ui/assets paths
# =========================
section "Configure OpenSearch Dashboards branding (local /ui/assets)"

# Remove old managed branding block (if any), then append the current one.
if grep -q "Recursive-IR Branding block (managed by installer)" "${DASH_YML}"; then
  awk '
    BEGIN{drop=0}
    /######## Recursive-IR Branding block \(managed by installer\) ########/{drop=1; next}
    /######## End Recursive-IR Branding block ########/{drop=0; next}
    drop==0{print}
  ' "${DASH_YML}" > "${DASH_YML}.tmp"
  mv "${DASH_YML}.tmp" "${DASH_YML}"
fi

cat >> "${DASH_YML}" <<'EOF'

######## Recursive-IR Branding block (managed by installer) ########
opensearchDashboards.branding:
  applicationTitle: "Recursive-IR"
  logo:
    defaultUrl: "/ui/assets/images/recursive-ir-banner.png"
    darkModeUrl: "/ui/assets/images/recursive-ir-banner.png"
  mark:
    defaultUrl: "/ui/assets/images/recursive-ir-logo-dark.png"
    darkModeUrl: "/ui/assets/images/recursive-ir-logo-dark.png"
  loadingLogo:
    defaultUrl: "/ui/assets/images/recursive-ir-spinner-light.gif"
    darkModeUrl: "/ui/assets/images/recursive-ir-spinner-light.gif"
  faviconUrl: "/ui/assets/images/recursive-ir-logo-dark.png"

opensearch_security.ui.basicauth.login.brandimage: "/ui/assets/images/recursive-ir-banner-light.png"
opensearch_security.ui.basicauth.login.title: "Welcome to Recursive-IR"
######## End Recursive-IR Branding block ########
EOF

systemctl restart opensearch-dashboards

# =========================
# Install Recursive-IR systemd units for Logstash + Filebeat
# (use your shipped configs under /etc/recursive-ir)
# =========================
section "Install Recursive-IR systemd units for Logstash + Filebeat"

mkdir -p "${RI_LOGSTASH_ETC}" "${RI_FILEBEAT_ETC}" "${RI_ETC_BASE}/conf"

# Ensure data/log dirs expected by your units and shipped configs
mkdir -p \
  /var/lib/recursive-ir/{logstash,filebeat} \
  /var/log/recursive-ir/{logstash,filebeat}

# Logstash user is typically created by package, but keep safe:
id -u logstash >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin logstash

cat > /etc/systemd/system/logstash.service <<'UNIT'
[Unit]
Description=Logstash (Recursive-IR)
After=network.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/recursive-ir/conf/recursive.env
User=logstash
Group=logstash
ExecStart=/usr/share/logstash/bin/logstash --path.settings /etc/recursive-ir/logstash
Restart=always
WorkingDirectory=/usr/share/logstash
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/filebeat.service <<'UNIT'
[Unit]
Description=Filebeat (Recursive-IR)
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/share/filebeat/filebeat -e -c /etc/recursive-ir/filebeat/filebeat.yml \
  -E path.home=/usr/share/filebeat \
  -E path.config=/etc/recursive-ir/filebeat \
  -E path.data=/var/lib/recursive-ir/filebeat \
  -E path.logs=/var/log/recursive-ir/filebeat
Restart=always

[Install]
WantedBy=multi-user.target
UNIT

chown -R logstash:logstash /var/lib/recursive-ir/logstash /var/log/recursive-ir/logstash || true
chown -R root:root /var/lib/recursive-ir/filebeat /var/log/recursive-ir/filebeat || true

systemctl daemon-reload
systemctl enable logstash filebeat

# We do NOT start Logstash/Filebeat automatically unless configs exist.
# - Logstash unit requires recursive.env
# - Filebeat requires filebeat.yml
# You said dfir init --bootstrap-env will create recursive.env from sample.
if [[ -f "${RI_CONF_ENV}" ]]; then
  systemctl start logstash || true
else
  echo "NOTE: ${RI_CONF_ENV} not found yet; Logstash not started."
fi

if [[ -f "${RI_FILEBEAT_ETC}/filebeat.yml" ]]; then
  systemctl start filebeat || true
else
  echo "NOTE: ${RI_FILEBEAT_ETC}/filebeat.yml not found yet; Filebeat not started."
fi

# =========================
# Verification + Summary
# =========================
section "Verification: OpenSearch TLS/auth (no -k)"
OS_TLS_OK="FAIL"
if curl --fail --silent \
  --cacert "${RI_CA}" \
  -u "admin:${OS_PASS}" \
  "${OS_URL_LOCAL}" >/dev/null; then
  OS_TLS_OK="OK"
fi

section "Collect versions + service statuses"
OS_VER="$(dpkg_ver opensearch || true)"
OSD_VER="$(dpkg_ver opensearch-dashboards || true)"
LS_VER="$(dpkg_ver logstash || true)"
FB_VER="$(dpkg_ver filebeat || true)"

OS_STATUS="$(systemctl is-active opensearch || true)"
OSD_STATUS="$(systemctl is-active opensearch-dashboards || true)"
LS_STATUS="$(systemctl is-active logstash || true)"
FB_STATUS="$(systemctl is-active filebeat || true)"

CLUSTER_STATUS="unknown"
if [[ "${OS_TLS_OK}" == "OK" ]]; then
  CLUSTER_STATUS="$(curl --silent --cacert "${RI_CA}" \
    -u "admin:${OS_PASS}" \
    "${OS_URL_LOCAL}/_cluster/health" \
    | sed -n 's/.*"status":"\([^"]*\)".*/\1/p' | head -n1 || true)"
  [[ -n "${CLUSTER_STATUS}" ]] || CLUSTER_STATUS="unknown"
fi

echo
echo "============================================================"
echo "Recursive-IR Stack Installation Summary"
echo "============================================================"
printf "%-28s %s\n" "OpenSearch:" "${OS_VER:-unknown}"
printf "%-28s %s\n" "OpenSearch Dashboards:" "${OSD_VER:-unknown}"
printf "%-28s %s\n" "Logstash:" "${LS_VER:-unknown}"
printf "%-28s %s\n" "Filebeat:" "${FB_VER:-unknown}"
echo
printf "%-28s %s\n" "OpenSearch TLS Check:" "${OS_TLS_OK}"
printf "%-28s %s\n" "Cluster Health:" "${CLUSTER_STATUS}"
printf "%-28s %s\n" "OpenSearch Service:" "${OS_STATUS}"
printf "%-28s %s\n" "Dashboards Service:" "${OSD_STATUS}"
printf "%-28s %s\n" "Logstash Service:" "${LS_STATUS}"
printf "%-28s %s\n" "Filebeat Service:" "${FB_STATUS}"
echo "============================================================"
echo

echo "Certs (canonical): ${RI_CERTS_OS}"
echo "  CA:       ${RI_CA}"
echo "  Node cert:${RI_NODE_CERT}"
echo "  Admin cert:${RI_ADMIN_CERT}"
echo

if [[ ! -f "${RI_CONF_ENV}" ]]; then
  echo "Next steps (Recursive-IR):"
  echo "  1) dfir init --bootstrap-env"
  echo "  2) Edit: ${RI_CONF_ENV}"
  echo "     - Ensure OS_CACERT points to: ${RI_CA}"
  echo "  3) systemctl start logstash filebeat"
else
  echo "Next steps: validate Logstash/Filebeat configs, then:"
  echo "  systemctl restart logstash filebeat"
fi

echo
echo "Useful checks:"
echo "  curl --cacert ${RI_CA} -u admin:<pass> ${OS_URL_LOCAL}/_cluster/health?pretty"
echo "  systemctl status opensearch opensearch-dashboards logstash filebeat"
echo "  journalctl -u opensearch -u opensearch-dashboards -u logstash -u filebeat -f"
