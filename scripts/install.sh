#!/bin/bash
# ------------------------------------------------------------------
# Recursive-IR installer script
# Copyright (c) 2026 Mark Jayson Alvarez
# Licensed under the Recursive-IR License
# ------------------------------------------------------------------
# OpenSearch + OpenSearch Dashboards + Logstash + Filebeat + Recursive-IR web ui/api, nginx
#
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
OPENSEARCH_INITIAL_ADMIN_PASSWORD="${OPENSEARCH_INITIAL_ADMIN_PASSWORD:-}"

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


detect_lan_ip() {
  local ipaddr

  ipaddr="$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
  [ -n "$ipaddr" ] && { echo "$ipaddr"; return 0; }

  ipaddr="$(hostname -I 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i !~ /^127\./){print $i; exit}}')"
  [ -n "$ipaddr" ] && { echo "$ipaddr"; return 0; }

  echo "127.0.0.1"
}

LAN_IP="$(detect_lan_ip)"

# =========================
# Pre-flight
# =========================
need_root
export DEBIAN_FRONTEND=noninteractive

if [[ -z "${OPENSEARCH_INITIAL_ADMIN_PASSWORD}" ]]; then
  echo "ERROR: Set OPENSEARCH_INITIAL_ADMIN_PASSWORD (required for OpenSearch fresh installs)."
  echo "Example:"
  echo "  sudo OPENSEARCH_INITIAL_ADMIN_PASSWORD='StrongPassHere' $0"
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
# Add OpenSearch APT repos + install
# =========================
section "Add OpenSearch APT repo and install OpenSearch + Dashboards"

install -m 0755 -d /etc/apt/keyrings

# Use the official keyring name/path (matches OpenSearch docs)
curl -fsSL https://artifacts.opensearch.org/publickeys/opensearch-release.pgp \
  | gpg --dearmor --batch --yes -o /etc/apt/keyrings/opensearch-release-keyring

chmod 0644 /etc/apt/keyrings/opensearch-release-keyring

# Remove any existing list files that reference the same OpenSearch repo with a different signed-by,
# which triggers: "Conflicting values set for option Signed-By ..."
for f in /etc/apt/sources.list.d/*.list; do
  [[ -f "$f" ]] || continue
  if grep -qE 'artifacts\.opensearch\.org/releases/bundle/opensearch/' "$f" \
     || grep -qE 'artifacts\.opensearch\.org/releases/bundle/opensearch-dashboards/' "$f"; then
    rm -f "$f"
  fi
done

# OpenSearch repo
cat > /etc/apt/sources.list.d/opensearch-${OS_APT_MAJOR}.list <<EOF
deb [signed-by=/etc/apt/keyrings/opensearch-release-keyring] https://artifacts.opensearch.org/releases/bundle/opensearch/${OS_APT_MAJOR}/apt stable main
EOF

# OpenSearch Dashboards repo (THIS is what fixes "Unable to locate package opensearch-dashboards")
cat > /etc/apt/sources.list.d/opensearch-dashboards-${OS_APT_MAJOR}.list <<EOF
deb [signed-by=/etc/apt/keyrings/opensearch-release-keyring] https://artifacts.opensearch.org/releases/bundle/opensearch-dashboards/${OS_APT_MAJOR}/apt stable main
EOF

# Tolerate releaseinfo change if needed
if ! apt-get update; then
  apt-get update --allow-releaseinfo-change
fi

env OPENSEARCH_INITIAL_ADMIN_PASSWORD="${OPENSEARCH_INITIAL_ADMIN_PASSWORD}" \
  apt-get install -y opensearch opensearch-dashboards

# -------------------------
# Ensure OpenSearch keystore exists before first start
# (prevents: unable to create temporary keystore /etc/opensearch/opensearch.keystore.tmp)
# -------------------------
if [ ! -f /etc/opensearch/opensearch.keystore ]; then
  echo "opensearch: creating /etc/opensearch/opensearch.keystore"
  /usr/share/opensearch/bin/opensearch-keystore create

  # Typical Debian/RPM perms: readable by root, group-readable by opensearch
  chown root:opensearch /etc/opensearch/opensearch.keystore
  chmod 0640 /etc/opensearch/opensearch.keystore
fi

systemctl enable opensearch opensearch-dashboards

# =========================
# Install Logstash + Filebeat from latest tarballs
# =========================
section "Install Logstash + Filebeat from latest Elastic tarballs"

RI_TMP_DL="/tmp/recursive-ir-elastic"
mkdir -p "${RI_TMP_DL}"

echo "Checking for the latest Elastic version..."
ELASTIC_VERSION="$(curl -fsSL https://api.github.com/repos/elastic/logstash/tags | grep -m 1 '"name":' | cut -d '"' -f 4 | sed 's/^v//')"

if [[ -z "${ELASTIC_VERSION}" ]]; then
  echo "ERROR: Could not determine the latest Elastic version."
  exit 1
fi

echo "Latest version found: ${ELASTIC_VERSION}"

ARCH="linux-x86_64"
BASE_URL="https://artifacts.elastic.co/downloads"
LOGSTASH_URL="${BASE_URL}/logstash/logstash-oss-${ELASTIC_VERSION}-${ARCH}.tar.gz"
FILEBEAT_URL="${BASE_URL}/beats/filebeat/filebeat-${ELASTIC_VERSION}-${ARCH}.tar.gz"

LS_TGZ="${RI_TMP_DL}/logstash-oss-${ELASTIC_VERSION}-${ARCH}.tar.gz"
FB_TGZ="${RI_TMP_DL}/filebeat-${ELASTIC_VERSION}-${ARCH}.tar.gz"

echo "Downloading Logstash from: ${LOGSTASH_URL}"
curl -fL -o "${LS_TGZ}" "${LOGSTASH_URL}"

echo "Downloading Filebeat from: ${FILEBEAT_URL}"
curl -fL -o "${FB_TGZ}" "${FILEBEAT_URL}"

rm -rf \
  /usr/share/recursive-ir/logstash \
  /usr/share/recursive-ir/filebeat \
  /usr/share/recursive-ir/logstash-* \
  /usr/share/recursive-ir/filebeat-*
mkdir -p /usr/share/recursive-ir

LS_EXTRACTED_DIR="${RI_TMP_DL}/logstash-${ELASTIC_VERSION}"
FB_EXTRACTED_DIR="${RI_TMP_DL}/filebeat-${ELASTIC_VERSION}-${ARCH}"

rm -rf "${LS_EXTRACTED_DIR}" "${FB_EXTRACTED_DIR}"

tar -xzf "${LS_TGZ}" -C "${RI_TMP_DL}"
tar -xzf "${FB_TGZ}" -C "${RI_TMP_DL}"

LS_INSTALL_DIR="/usr/share/recursive-ir/logstash-${ELASTIC_VERSION}"
FB_INSTALL_DIR="/usr/share/recursive-ir/filebeat-${ELASTIC_VERSION}-${ARCH}"

if [[ ! -d "${LS_EXTRACTED_DIR}" ]]; then
  echo "ERROR: expected extracted Logstash dir not found: ${LS_EXTRACTED_DIR}"
  exit 1
fi

if [[ ! -d "${FB_EXTRACTED_DIR}" ]]; then
  echo "ERROR: expected extracted Filebeat dir not found: ${FB_EXTRACTED_DIR}"
  exit 1
fi

rm -rf "${LS_INSTALL_DIR}" "${FB_INSTALL_DIR}"

cp -a "${LS_EXTRACTED_DIR}" "${LS_INSTALL_DIR}"
cp -a "${FB_EXTRACTED_DIR}" "${FB_INSTALL_DIR}"

ln -sfn "${LS_INSTALL_DIR}" /usr/share/recursive-ir/logstash
ln -sfn "${FB_INSTALL_DIR}" /usr/share/recursive-ir/filebeat

# Ensure logstash service user exists before assigning ownership
id -u logstash >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin logstash

chown -R logstash:logstash "${LS_INSTALL_DIR}"
chown -h logstash:logstash /usr/share/recursive-ir/logstash

chown -R root:root "${FB_INSTALL_DIR}"
chown -h root:root /usr/share/recursive-ir/filebeat

# Sanity-check expected tarball layout before proceeding
if [[ ! -x /usr/share/recursive-ir/logstash/bin/logstash ]]; then
  echo "ERROR: expected Logstash binary not found at /usr/share/recursive-ir/logstash/bin/logstash"
  exit 1
fi

if [[ ! -x /usr/share/recursive-ir/logstash/bin/logstash-plugin ]]; then
  echo "ERROR: expected logstash-plugin not found at /usr/share/recursive-ir/logstash/bin/logstash-plugin"
  exit 1
fi

if [[ ! -x /usr/share/recursive-ir/filebeat/filebeat ]]; then
  echo "ERROR: expected Filebeat binary not found at /usr/share/recursive-ir/filebeat/filebeat"
  exit 1
fi

# Install OpenSearch output plugin into the Recursive-IR Logstash tree
LS_PLUGIN_BIN="/usr/share/recursive-ir/logstash/bin/logstash-plugin"

if [[ ! -x "${LS_PLUGIN_BIN}" ]]; then
  echo "ERROR: could not find logstash-plugin at ${LS_PLUGIN_BIN}"
  exit 1
fi

echo "Using Logstash plugin manager: ${LS_PLUGIN_BIN}"

echo "Checking for logstash-output-opensearch plugin..."

if "${LS_PLUGIN_BIN}" list --verbose 2>/tmp/ri-logstash-plugin-list.err | grep -q '^logstash-output-opensearch '; then
  echo "logstash-output-opensearch already installed"
else
  echo "Installing logstash-output-opensearch..."
  if ! "${LS_PLUGIN_BIN}" install logstash-output-opensearch; then
    echo "ERROR: failed to install logstash-output-opensearch"
    exit 1
  fi
fi

echo "Verifying logstash-output-opensearch..."
if ! "${LS_PLUGIN_BIN}" list --verbose 2>/tmp/ri-logstash-plugin-list.err | grep -q '^logstash-output-opensearch '; then
  echo "ERROR: logstash-output-opensearch not visible after install"
  cat /tmp/ri-logstash-plugin-list.err 2>/dev/null || true
  exit 1
fi

# Stop any pre-existing services before we install/update our own units later
systemctl stop logstash 2>/dev/null || true
systemctl stop filebeat 2>/dev/null || true
systemctl disable logstash 2>/dev/null || true
systemctl disable filebeat 2>/dev/null || true

# =========================
# Generate TLS certs (non-interactive)
# =========================
#
# ------------------------------------------------------------------
# Remove OpenSearch demo certificates
# ------------------------------------------------------------------
echo "[+] Removing demo certificates"
sudo sh -c 'rm -f /etc/opensearch/*.pem'
sudo sh -c 'rm -f /etc/opensearch/*temp.pem /etc/opensearch/*.csr /etc/opensearch/*.ext'

section "Generate OpenSearch TLS (self-signed CA) under ${RI_CERTS_OS}"
mkdir -p "${RI_CERTS_OS}"
chown root:opensearch "${RI_CERTS_OS}"
chmod 0750 "${RI_CERTS_OS}"

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

# ------------------------------------------------------------------
# TLS file permissions
# - OpenSearch runtime needs: CA cert, node cert, node key
# - OpenSearch Dashboards needs: CA cert (public) to trust https
# - Keep CA key + admin key root-only
# ------------------------------------------------------------------

# Allow traversal for BOTH opensearch + opensearch-dashboards (simple mode)
# Dashboards must be able to reach the CA file path; easiest is +x for others on dirs.
sudo chown root:opensearch "${RI_ETC_BASE}" "${RI_ETC_BASE}/certs" "${RI_CERTS_OS}"
sudo chmod 0755 "${RI_ETC_BASE}" "${RI_ETC_BASE}/certs" "${RI_CERTS_OS}"

# Make sure opensearch can traverse /etc/opensearch (paranoia)
sudo chown root:opensearch /etc/opensearch
sudo chmod 0770 /etc/opensearch

# --- OpenSearch runtime TLS material ---
# CA is public; Dashboards reads it too.
sudo chown root:opensearch "${RI_CA}"
sudo chmod 0644 "${RI_CA}"

# ------------------------------------------------------------------
# Trust Recursive-IR root CA system-wide (so curl/dfir can talk to https://127.0.0.1:9200)
# ------------------------------------------------------------------
section "Install Recursive-IR root CA into system trust store"

RI_CA_DST="/usr/local/share/ca-certificates/recursive-ir-root-ca.crt"
install -m 0644 "${RI_CA}" "${RI_CA_DST}"
update-ca-certificates

# Node cert can be group-readable.
sudo chown root:opensearch "${RI_NODE_CERT}"
sudo chmod 0640 "${RI_NODE_CERT}"

# Node key MUST be readable by the opensearch service user.
# Tightest: make opensearch the owner and keep 0600.
sudo chown opensearch:opensearch "${RI_NODE_KEY}"
sudo chmod 0600 "${RI_NODE_KEY}"

# --- Root-only secrets (service does NOT need these) ---
sudo chown root:root "${RI_CA_KEY}" "${RI_ADMIN_KEY}"
sudo chmod 0600 "${RI_CA_KEY}" "${RI_ADMIN_KEY}"

# Admin cert not needed by the running service; keep it readable for root
sudo chown root:root "${RI_ADMIN_CERT}"
sudo chmod 0644 "${RI_ADMIN_CERT}"

# (Optional) serial file isn't needed by the service; keep it root-only or group-readable
# chown root:root "${RI_CERTS_OS}/root-ca.srl" 2>/dev/null || true
# chmod 0644 "${RI_CERTS_OS}/root-ca.srl" 2>/dev/null || true
#
# ------------------------------------------------------------------
# Remove OpenSearch demo security configuration
# ------------------------------------------------------------------

OSYML="/etc/opensearch/opensearch.yml"

if grep -q "Start OpenSearch Security Demo Configuration" "$OSYML"; then
    echo "[+] Removing OpenSearch demo security configuration block"
    
    sudo sed -i '/Start OpenSearch Security Demo Configuration/,/End OpenSearch Security Demo Configuration/d' "$OSYML"
fi

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

# -------------------------
# Normalize OpenSearch runtime dirs (avoid permission drift across reruns)
# -------------------------
mkdir -p /var/log/opensearch /var/lib/opensearch
chown -R opensearch:opensearch /var/log/opensearch /var/lib/opensearch
chmod 0750 /var/log/opensearch /var/lib/opensearch

# JVM hard-fails if it can't open gc.log
rm -f /var/log/opensearch/gc.log
sudo -u opensearch touch /var/log/opensearch/gc.log
chown opensearch:opensearch /var/log/opensearch/gc.log
chmod 0640 /var/log/opensearch/gc.log

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

OPENSEARCH_JAVA_HOME=/usr/share/opensearch/jdk "${OS_SEC_TOOLS}" \
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

# Ensure OpenSearch Dashboards trusts the Recursive-IR CA
if ! grep -q "Recursive-IR Dashboards block" "${DASH_YML}"; then
  cat >> "${DASH_YML}" <<EOF

# Recursive-IR Dashboards block (managed by installer)
opensearch.ssl.certificateAuthorities: ["/etc/ssl/certs/ca-certificates.crt"]
# End Recursive-IR Dashboards block
EOF
fi

# =========================
# Install Recursive-IR branding assets into OpenSearch Dashboards
# =========================
section "Install Recursive-IR branding assets"

# Source images ONLY from repo UI build output
SRC_IMAGES=""

if [[ -n "${RI_REPO_ROOT:-}" && -d "${RI_REPO_ROOT}/web/ui/dist/assets/images" ]]; then
  SRC_IMAGES="${RI_REPO_ROOT}/web/ui/dist/assets/images"

elif [[ -d "./web/ui/dist/assets/images" ]]; then
  SRC_IMAGES="./web/ui/dist/assets/images"
fi

if [[ -z "${SRC_IMAGES}" ]]; then
  echo "[branding] ERROR: UI build output not found."
  echo "Expected:"
  echo "  web/ui/dist/assets/images"
  echo ""
  echo "Run the UI build first."
  exit 1
fi

echo "[branding] Using source images: ${SRC_IMAGES}"

OSD_HOME="/usr/share/opensearch-dashboards"

# Determine Dashboards assets root
ASSETS_ROOT=""
for d in \
  "${OSD_HOME}/assets" \
  "${OSD_HOME}/ui/assets" \
  "${OSD_HOME}/src/core/server/core_app/assets" \
  "${OSD_HOME}/core/server/core_app/assets" \
; do
  if [[ -d "$d" ]]; then
    ASSETS_ROOT="$d"
    break
  fi
done

if [[ -z "${ASSETS_ROOT}" ]]; then
  echo "[branding] ERROR: could not locate Dashboards assets directory."
  exit 1
fi

# Match working dev layout
RI_ASSETS_DIR="${ASSETS_ROOT}/recursive-ir"
mkdir -p "${RI_ASSETS_DIR}"

install -m 0644 "${SRC_IMAGES}/recursive-ir-banner.png"        "${RI_ASSETS_DIR}/"
install -m 0644 "${SRC_IMAGES}/recursive-ir-banner-light.png"  "${RI_ASSETS_DIR}/"
install -m 0644 "${SRC_IMAGES}/recursive-ir-logo-dark.png"     "${RI_ASSETS_DIR}/"
install -m 0644 "${SRC_IMAGES}/recursive-ir-logo-light.png"    "${RI_ASSETS_DIR}/"
install -m 0644 "${SRC_IMAGES}/recursive-ir-spinner-light.gif" "${RI_ASSETS_DIR}/"

echo "[branding] Installed images into: ${RI_ASSETS_DIR}"
ls -la "${RI_ASSETS_DIR}" | sed -n '1,120p'

# =========================
# Configure OpenSearch Dashboards branding
# =========================
section "Configure OpenSearch Dashboards branding"

# Remove old managed block
if grep -q "Recursive-IR Branding block (managed by installer)" "${DASH_YML}"; then
  awk '
    BEGIN{drop=0}
    /######## Recursive-IR Branding block \(managed by installer\) ########/{drop=1; next}
    /######## End Recursive-IR Branding block ########/{drop=0; next}
    drop==0{print}
  ' "${DASH_YML}" > "${DASH_YML}.tmp"
  mv "${DASH_YML}.tmp" "${DASH_YML}"
fi

# Append branding block
cat >> "${DASH_YML}" <<'EOF'

######## Recursive-IR Branding block (managed by installer) ########
opensearchDashboards.branding:
  applicationTitle: "Recursive-IR"
  logo:
    defaultUrl: "/ui/assets/recursive-ir/recursive-ir-banner.png"
    darkModeUrl: "/ui/assets/recursive-ir/recursive-ir-banner.png"
  mark:
    defaultUrl: "/ui/assets/recursive-ir/recursive-ir-logo-dark.png"
    darkModeUrl: "/ui/assets/recursive-ir/recursive-ir-logo-dark.png"
  loadingLogo:
    defaultUrl: "/ui/assets/recursive-ir/recursive-ir-spinner-light.gif"
    darkModeUrl: "/ui/assets/recursive-ir/recursive-ir-spinner-light.gif"
  faviconUrl: "/ui/assets/recursive-ir/recursive-ir-logo-dark.png"

opensearch_security.ui.basicauth.login.brandimage: "/ui/assets/recursive-ir/recursive-ir-banner-light.png"
opensearch_security.ui.basicauth.login.title: "Welcome to Recursive-IR"
######## End Recursive-IR Branding block ########
EOF


mkdir -p /var/lib/opensearch/nodes
chown -R opensearch:opensearch /var/lib/opensearch
chmod 0750 /var/lib/opensearch

systemctl restart opensearch-dashboards

# =========================
# Install Recursive-IR systemd units for Logstash + Filebeat (tarball install)
# - Install our units pointing at /etc/recursive-ir configs
# =========================
#
section "Install Recursive-IR systemd units for Logstash + Filebeat"

mkdir -p "${RI_LOGSTASH_ETC}" "${RI_FILEBEAT_ETC}" "${RI_ETC_BASE}/conf"

# Ensure data/log dirs expected by our units and shipped configs
mkdir -p \
  /var/lib/recursive-ir/{logstash,filebeat} \
  /var/log/recursive-ir/{logstash,filebeat}

# Stop/disable any pre-existing units before installing Recursive-IR-managed ones.
systemctl stop filebeat logstash 2>/dev/null || true
systemctl disable filebeat logstash 2>/dev/null || true
systemctl reset-failed filebeat logstash 2>/dev/null || true

# Logstash user is typically created by package, but keep safe:
id -u logstash >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin logstash
# Ensure installed tarball trees + symlink have the expected ownership
chown -R logstash:logstash /usr/share/recursive-ir/logstash-* 2>/dev/null || true
chown -h logstash:logstash /usr/share/recursive-ir/logstash 2>/dev/null || true

chown -R root:root /usr/share/recursive-ir/filebeat-* 2>/dev/null || true
chown -h root:root /usr/share/recursive-ir/filebeat 2>/dev/null || true

# ---- Logstash (Recursive-IR override unit) ----
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
ExecStart=/usr/share/recursive-ir/logstash/bin/logstash --path.settings /etc/recursive-ir/logstash
Restart=always
WorkingDirectory=/usr/share/recursive-ir/logstash
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536
TimeoutStopSec=infinity

[Install]
WantedBy=multi-user.target
UNIT

# ---- Filebeat (Recursive-IR unit) ----
cat > /etc/systemd/system/filebeat.service <<'UNIT'
[Unit]
Description=Filebeat (Recursive-IR)
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/share/recursive-ir/filebeat/filebeat -e -c /etc/recursive-ir/filebeat/filebeat.yml \
  -E path.home=/usr/share/recursive-ir/filebeat \
  -E path.config=/etc/recursive-ir/filebeat \
  -E path.data=/var/lib/recursive-ir/filebeat \
  -E path.logs=/var/log/recursive-ir/filebeat
Restart=always

[Install]
WantedBy=multi-user.target
UNIT

section "Install required runtime libraries"

apt-get install -y libcurl4 unzip

chown -R logstash:logstash /var/lib/recursive-ir/logstash /var/log/recursive-ir/logstash || true
chown -R root:root       /var/lib/recursive-ir/filebeat /var/log/recursive-ir/filebeat || true

systemctl daemon-reload
systemctl enable logstash filebeat

# =========================
# Bootstrap Recursive-IR environment
# =========================
section "Bootstrap Recursive-IR (dfir init)"

if [[ ! -x "./bin/dfir" ]]; then
  echo "ERROR: ./bin/dfir not found. Run installer from the Recursive-IR repo root."
  exit 1
fi

sudo ./bin/dfir init --bootstrap-env --enable --create-recursive-user


# =========================
# Update generated recursive.env
# =========================
section "Configure /etc/recursive-ir/conf/recursive.env"

if [[ ! -f "${RI_CONF_ENV}" ]]; then
  echo "ERROR: ${RI_CONF_ENV} was not created by dfir init"
  exit 1
fi

sed -i \
  -e 's|^OS_USER=.*|OS_USER="admin"|' \
  -e "s|^OS_PASS=.*|OS_PASS=\"${OPENSEARCH_INITIAL_ADMIN_PASSWORD}\"|" \
  -e "s|^OSD_HOST_LAN=.*|OSD_HOST_LAN=\"http://${LAN_IP}\"|" \
  "${RI_CONF_ENV}"

# Start services only after their configs exist.
if [[ -f "${RI_CONF_ENV}" ]]; then
  systemctl start logstash || echo "WARNING: failed to start logstash"
else
  echo "NOTE: ${RI_CONF_ENV} not found yet; Logstash not started."
fi

if [[ -f "${RI_FILEBEAT_ETC}/filebeat.yml" ]]; then
  systemctl start filebeat || echo "WARNING: failed to start filebeat"
else
  echo "NOTE: ${RI_FILEBEAT_ETC}/filebeat.yml not found yet; Filebeat not started."
fi

# =========================
# Install Docker
# =========================
section "Install Docker"

if ! command -v docker >/dev/null 2>&1; then
  apt-get update
  apt-get install -y ca-certificates curl gnupg

  install -m 0755 -d /etc/apt/keyrings

  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg

  chmod a+r /etc/apt/keyrings/docker.gpg

  echo \
"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu \
$(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    > /etc/apt/sources.list.d/docker.list

  apt-get update

  apt-get install -y \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin

  systemctl enable --now docker
else
  echo "Docker already installed; skipping package install."
fi

# =========================
# Deploy Recursive-IR Web stack
# =========================
section "Deploy Recursive-IR Web UI, API, and Nginx"

if [[ ! -f "${RI_CONF_ENV}" ]]; then
  echo "ERROR: ${RI_CONF_ENV} not found; cannot deploy Docker web stack."
  exit 1
fi

if [[ ! -d "web" ]]; then
  echo "ERROR: web/ directory not found. Run installer from the Recursive-IR repo root."
  exit 1
fi

(
  cd web
  docker compose --env-file "${RI_CONF_ENV}" up -d --pull always
)


# =========================
# Verification + Summary
# =========================
section "Verification: OpenSearch TLS/auth (no -k)"
OS_TLS_OK="FAIL"

# TLS verification only (no auth required)
if curl --silent --cacert "${RI_CA}" "${OS_URL_LOCAL}" >/dev/null; then
  OS_TLS_OK="OK"
fi

section "Collect versions + service statuses"
OS_VER="$(dpkg_ver opensearch || true)"
OSD_VER="$(dpkg_ver opensearch-dashboards || true)"

LS_VER="unknown"
FB_VER="unknown"

if [[ -L /usr/share/recursive-ir/logstash ]]; then
  LS_VER="$(basename "$(readlink -f /usr/share/recursive-ir/logstash)")"
  LS_VER="${LS_VER#logstash-}"
fi

if [[ -L /usr/share/recursive-ir/filebeat ]]; then
  FB_VER="$(basename "$(readlink -f /usr/share/recursive-ir/filebeat)")"
  FB_VER="${FB_VER#filebeat-}"
  FB_VER="${FB_VER%-linux-x86_64}"
fi

OS_STATUS="$(systemctl is-active opensearch || true)"
OSD_STATUS="$(systemctl is-active opensearch-dashboards || true)"
LS_STATUS="$(systemctl is-active logstash || true)"
FB_STATUS="$(systemctl is-active filebeat || true)"

CLUSTER_STATUS="unknown"
if [[ "${OS_TLS_OK}" == "OK" ]]; then
  CLUSTER_STATUS="$(curl --silent --cacert "${RI_CA}" \
    -u "admin:${OPENSEARCH_INITIAL_ADMIN_PASSWORD}" \
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
