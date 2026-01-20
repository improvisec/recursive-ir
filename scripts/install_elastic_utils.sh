# ------------------------------------------------------------------
# Recursive-IR helper script
# Copyright (c) 2026 Mark Jayson Alvarez
# Licensed under the Recursive-IR License
# ------------------------------------------------------------------
#!/usr/bin/env bash
set -euo pipefail

# === SETTINGS (override via env if needed) ===
SRC_DIR="${SRC_DIR:-/home/recursive}"
LS_SRC="${LS_SRC:-}"     # e.g., /home/recursive/logstash-9.1.4
FB_SRC="${FB_SRC:-}"     # e.g., /home/recursive/filebeat-9.1.4-linux-x86_64


# Paths
ETC_BASE="/etc/recursive-ir"
LS_ETC="${ETC_BASE}/logstash"
RI_ETC="${ETC_BASE}/conf"
FB_ETC="${ETC_BASE}/filebeat"

# === Pre-flight ===
if [[ $EUID -ne 0 ]]; then
  echo "Run as root (sudo)." >&2
  exit 1
fi
command -v systemctl >/dev/null || { echo "systemd is required."; exit 1; }

# Auto-detect extracted folders if not provided
if [[ -z "${LS_SRC}" ]]; then
  LS_SRC="$(ls -d ${SRC_DIR}/logstash-* 2>/dev/null | head -n1 || true)"
fi
if [[ -z "${FB_SRC}" ]]; then
  FB_SRC="$(ls -d ${SRC_DIR}/filebeat-*linux-x86_64 2>/dev/null | head -n1 || true)"
fi

[[ -d "${LS_SRC}" ]] || { echo "Logstash source dir not found. Set LS_SRC or place under ${SRC_DIR}/logstash-*/"; exit 1; }
[[ -d "${FB_SRC}" ]] || { echo "Filebeat source dir not found. Set FB_SRC or place under ${SRC_DIR}/filebeat-*-linux-x86_64/"; exit 1; }

echo "Using Logstash source: ${LS_SRC}"
echo "Using Filebeat source: ${FB_SRC}"

# Stop existing services if present
systemctl stop filebeat 2>/dev/null || true
systemctl stop logstash 2>/dev/null || true

# === Install binaries to /usr/share ===
rm -rf /usr/share/recursive-ir/logstash /usr/share/recursive-ir/filebeat
mkdir -p /usr/share/recursive-ir
cp -a "${LS_SRC}" /usr/share/recursive-ir/logstash
cp -a "${FB_SRC}" /usr/share/recursive-ir/filebeat

# === Users & dirs ===
id -u logstash &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin logstash

mkdir -p "${LS_ETC}"/pipelines \
         "${FB_ETC}"/inputs.d \
         /var/lib/recursive-ir/{logstash,filebeat} \
         /var/log/recursive-ir/{logstash,filebeat} \

# === Environment convenience (optional PATHs) ===
tee /etc/profile.d/elastic.sh >/dev/null <<'EOF'
export LOGSTASH_HOME=/usr/share/recursive-ir/logstash
export FILEBEAT_HOME=/usr/share/recursive-ir/filebeat
export PATH=$PATH:$LOGSTASH_HOME/bin:$FILEBEAT_HOME
EOF



# Install OpenSearch output plugin if missing
if ! /usr/share/recursive-ir/logstash/bin/logstash-plugin list | grep -q '^logstash-output-opensearch$'; then
  /usr/share/recursive-ir/logstash/bin/logstash-plugin install logstash-output-opensearch
fi


# Copy certificates used by OpenSearch
mkdir -p /etc/recursive-ir/logstash/certs
cp /etc/opensearch/root-ca.pem /etc/recursive-ir/logstash/certs/opensearch-ca.pem
chown -R logstash:logstash /etc/recursive-ir/logstash/certs
chmod 644 /etc/recursive-ir/logstash/certs/opensearch-ca.pem


# Ownership for Logstash
chown -R logstash:logstash "${LS_ETC}" "${RI_ETC}" /var/lib/recursive-ir/logstash /var/log/recursive-ir/logstash /usr/share/recursive-ir/logstash || true


# Strict perms for Filebeat
chown -R root:root "${FB_ETC}" /usr/share/recursive-ir/filebeat /var/lib/recursive-ir/filebeat /var/log/recursive-ir/filebeat
chmod 600 "${FB_ETC}/filebeat.yml"

# === systemd units ===

tee /etc/systemd/system/logstash.service >/dev/null <<'UNIT'
# ------------------------------------------------------------------
# Recursive-IR systemd file
# Copyright (c) 2026 Mark Jayson Alvarez
# Licensed under the Recursive-IR License
# ------------------------------------------------------------------
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

[Install]
WantedBy=multi-user.target
UNIT

tee /etc/systemd/system/filebeat.service >/dev/null <<'UNIT'
# ------------------------------------------------------------------
# Recursive-IR systemd file
# Copyright (c) 2026 Mark Jayson Alvarez
# Licensed under the Recursive-IR License
# ------------------------------------------------------------------
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

# === Enable & start ===
systemctl daemon-reload
systemctl enable logstash filebeat
systemctl restart logstash
sleep 2
systemctl restart filebeat

