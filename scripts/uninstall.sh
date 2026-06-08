#!/usr/bin/env bash
#
# Recursive-IR Uninstall Script
# Copyright (c) 2026 Mark Alvarez 
#
# Removes Recursive-IR, OpenSearch stack, services,
# Docker Compose deployment, configuration, data, and installer-created users.
#

set -u

say() {
  printf '\n==> %s\n' "$*"
}

run() {
  echo "+ $*"
  "$@" || true
}

systemd_exists() {
  systemctl list-unit-files "$1" >/dev/null 2>&1 || systemctl status "$1" >/dev/null 2>&1
}

stop_disable_unit() {
  unit="$1"

  if systemd_exists "$unit"; then
    echo "+ systemctl stop $unit"
    systemctl stop "$unit" 2>/dev/null || true

    echo "+ systemctl disable $unit"
    systemctl disable "$unit" 2>/dev/null || true
  else
    echo "+ skip missing unit: $unit"
  fi
}

purge_if_known() {
  pkg="$1"

  if dpkg-query -W "$pkg" >/dev/null 2>&1; then
    echo "+ apt-get purge -y $pkg"
    apt-get purge -y "$pkg" || true
  else
    echo "+ skip missing package: $pkg"
  fi
}

print_uninstall_plan() {
  cat <<'EOF'

Recursive-IR uninstall plan

This script will remove:

Services and timers:
  dfir-worker.service
  dfir-watcher.service
  dfir-parser.service
  dfir-enricher.service
  dfir-parser.timer
  dfir-enricher.timer
  logstash.service
  filebeat.service
  opensearch.service
  opensearch-dashboards.service

APT packages:
  opensearch
  opensearch-dashboards

Tarball-installed applications:
  /usr/share/recursive-ir/logstash
  /usr/share/recursive-ir/filebeat

Docker Compose deployment:
  recursive-ir-ui
  recursive-ir-api
  recursive-ir-nginx

Directories and files:
  /etc/recursive-ir
  /var/lib/recursive-ir
  /var/log/recursive-ir
  /usr/share/recursive-ir
  /tmp/recursive-ir-elastic
  /usr/local/bin/dfir
  /etc/sudoers.d/recursive-ir
  /usr/local/share/ca-certificates/recursive-ir-root-ca.crt
  /etc/opensearch
  /etc/opensearch-dashboards
  /var/lib/opensearch
  /var/log/opensearch
  /usr/share/opensearch
  /usr/share/opensearch-dashboards

APT repositories and keyrings:
  OpenSearch repository and keyring
  OpenSearch Dashboards repository and keyring

Users:
  recursive
  dfir
  logstash
  filebeat
  opensearch
  opensearch-dashboards

Groups:
  recursive
  dfir
  logstash
  filebeat
  opensearch
  opensearch-dashboards

The following applications are not part of the Recursive-IR uninstall
and will be left installed:

  docker-ce
  docker-ce-cli
  containerd.io
  docker-buildx-plugin
  docker-compose-plugin

  openssl
  curl
  wget
  tar
  unzip
  gnupg2
  lsb-release
  ca-certificates
  apt-transport-https
  libcurl4

EOF
}

show_uninstall_plan() {
  if command -v less >/dev/null 2>&1; then
    print_uninstall_plan | less -R
  elif command -v more >/dev/null 2>&1; then
    print_uninstall_plan | more
  else
    print_uninstall_plan
  fi
}

confirm_uninstall() {
  show_uninstall_plan
  printf 'Proceed with uninstall? Type y or yes to continue: '
  read -r answer

  case "$answer" in
    y|Y|yes|YES)
      ;;
    *)
      echo "Cancelled."
      exit 0
      ;;
  esac
}

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  echo "ERROR: run as root, e.g. sudo bash $0" >&2
  exit 1
fi

confirm_uninstall

REPO_ROOT="$(pwd)"
COMPOSE_FILE=""

if [ -f "$REPO_ROOT/web/docker-compose.yml" ]; then
  COMPOSE_FILE="$REPO_ROOT/web/docker-compose.yml"
elif [ -f "$REPO_ROOT/web/docker/docker-compose.yml" ]; then
  COMPOSE_FILE="$REPO_ROOT/web/docker/docker-compose.yml"
elif [ -f "/opt/recursive-ir/web/docker-compose.yml" ]; then
  COMPOSE_FILE="/opt/recursive-ir/web/docker-compose.yml"
elif [ -f "/opt/recursive-ir/web/docker/docker-compose.yml" ]; then
  COMPOSE_FILE="/opt/recursive-ir/web/docker/docker-compose.yml"
fi

say "Stop Recursive-IR services and timers"
for unit in \
  dfir-worker.service \
  dfir-watcher.service \
  dfir-parser.service \
  dfir-enricher.service \
  dfir-parser.timer \
  dfir-enricher.timer \
  logstash.service \
  filebeat.service \
  opensearch-dashboards.service \
  opensearch.service
do
  stop_disable_unit "$unit"
done

say "Remove Recursive-IR Docker Compose deployment"
if command -v docker >/dev/null 2>&1; then
  if [ -n "$COMPOSE_FILE" ]; then
    if [ -f /etc/recursive-ir/env/recursive.env ]; then
      run docker compose --env-file /etc/recursive-ir/env/recursive.env -f "$COMPOSE_FILE" down -v --remove-orphans
    else
      run docker compose -f "$COMPOSE_FILE" down -v --remove-orphans
    fi
  fi

  docker ps -aq --filter "name=recursive-ir-ui" | xargs -r docker rm -f || true
  docker ps -aq --filter "name=recursive-ir-api" | xargs -r docker rm -f || true
  docker ps -aq --filter "name=recursive-ir-nginx" | xargs -r docker rm -f || true
fi

say "Remove Recursive-IR systemd units"
rm -f \
  /etc/systemd/system/dfir-worker.service \
  /etc/systemd/system/dfir-watcher.service \
  /etc/systemd/system/dfir-parser.service \
  /etc/systemd/system/dfir-parser.timer \
  /etc/systemd/system/dfir-enricher.service \
  /etc/systemd/system/dfir-enricher.timer \
  /etc/systemd/system/logstash.service \
  /etc/systemd/system/filebeat.service

run systemctl daemon-reload
run systemctl reset-failed

say "Purge OpenSearch packages"
run dpkg --configure -a

for pkg in \
  opensearch \
  opensearch-dashboards
do
  purge_if_known "$pkg"
done

say "Remove OpenSearch repositories and keyrings"
rm -f \
  /etc/apt/sources.list.d/opensearch-*.list \
  /etc/apt/sources.list.d/opensearch-dashboards-*.list \
  /etc/apt/keyrings/opensearch-release-keyring \
  /etc/apt/keyrings/opensearch*.gpg \
  /usr/share/keyrings/opensearch*.gpg

say "Remove OpenSearch SysV leftovers"
rm -f \
  /etc/rc*.d/*opensearch* \
  /etc/init.d/opensearch \
  /etc/init.d/opensearch-dashboards

say "Remove Recursive-IR files"
rm -rf \
  /etc/recursive-ir \
  /var/lib/recursive-ir \
  /var/log/recursive-ir \
  /usr/share/recursive-ir \
  /tmp/recursive-ir-elastic \
  /usr/local/bin/dfir \
  /etc/sudoers.d/recursive-ir \
  /usr/local/share/ca-certificates/recursive-ir-root-ca.crt

say "Remove OpenSearch leftovers"
rm -rf \
  /etc/opensearch \
  /etc/opensearch-dashboards \
  /var/lib/opensearch \
  /var/log/opensearch \
  /usr/share/opensearch \
  /usr/share/opensearch-dashboards

say "Remove installer-created users and groups"
for u in recursive dfir logstash filebeat opensearch opensearch-dashboards; do
  if id "$u" >/dev/null 2>&1; then
    pkill -KILL -u "$u" 2>/dev/null || true
    run userdel -r "$u"
  else
    echo "+ skip missing user: $u"
  fi
done

for g in recursive dfir logstash filebeat opensearch opensearch-dashboards; do
  if getent group "$g" >/dev/null 2>&1; then
    run groupdel "$g"
  else
    echo "+ skip missing group: $g"
  fi
done

say "Refresh systemd state"
run systemctl daemon-reload
run systemctl reset-failed

say "Leftover checks"
run bash -c "systemctl list-units --all 2>/dev/null | grep -Ei 'recursive|dfir|opensearch|dashboards|logstash|filebeat' || true"
run bash -c "docker ps -a --format '{{.Names}}' 2>/dev/null | grep -Ei '^recursive-ir-(ui|api|nginx)$' || true"
run bash -c "dpkg -l 2>/dev/null | grep -Ei 'opensearch|dashboards' || true"
run bash -c "getent passwd recursive dfir logstash filebeat opensearch opensearch-dashboards 2>/dev/null || true"
run bash -c "getent group recursive dfir logstash filebeat opensearch opensearch-dashboards 2>/dev/null || true"
run bash -c "find /etc /var/lib /var/log /opt -maxdepth 2 \( -iname '*recursive*' -o -iname '*opensearch*' -o -iname '*logstash*' -o -iname '*filebeat*' \) 2>/dev/null || true"

say "Uninstall finished"
