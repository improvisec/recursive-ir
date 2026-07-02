#!/usr/bin/env bash
# ------------------------------------------------------------------
# Recursive-IR update script
# Copyright (c) 2026 Mark Jayson Alvarez
# Licensed under the Recursive-IR License
# ------------------------------------------------------------------
#
# Safe update path for an existing installation.
#
# ------------------------------------------------------------------

set -euo pipefail

need_root() {
  [[ ${EUID:-0} -eq 0 ]] || {
    echo "Run as root: sudo $0"
    exit 1
  }
}

section() {
  echo
  echo "==> $*"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing command: $1"
    exit 1
  }
}

need_root
require_cmd git
require_cmd docker
require_cmd systemctl

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RI_CONF_ENV="/etc/recursive-ir/env/recursive.env"

if [[ ! -d "$ROOT/.git" ]]; then
    echo "ERROR: $ROOT is not a git repository."
    exit 1
fi

if [[ ! -f "$RI_CONF_ENV" ]]; then
    echo "ERROR: $RI_CONF_ENV not found."
    echo "Recursive-IR does not appear to be installed."
    exit 1
fi

if [[ ! -f "$ROOT/web/docker-compose.yml" ]]; then
    echo "ERROR: $ROOT/web/docker-compose.yml not found."
    exit 1
fi

OLD_VERSION="unknown"
NEW_VERSION="unknown"

if [[ -f "$ROOT/VERSION" ]]; then
    OLD_VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
fi

section "Update Recursive-IR repository"

echo "[update] Current version: $OLD_VERSION"
echo "[update] Running git pull --ff-only..."

set +e
PULL_OUTPUT="$(git -C "$ROOT" pull --ff-only 2>&1)"
PULL_STATUS=$?
set -e

echo "$PULL_OUTPUT"

if [[ "$PULL_STATUS" -ne 0 ]]; then
    echo
    echo "[update] ERROR: Failed to update repository."
    echo "[update] This usually means the local checkout has changes or commits that prevent a fast-forward update."
    echo
    echo "Run:"
    echo "  git -C \"$ROOT\" status"
    echo
    exit "$PULL_STATUS"
fi

if echo "$PULL_OUTPUT" | grep -Eiq "Already up[ -]to[ -]date"; then
    echo
    echo "[update] Recursive-IR is already up to date."
    echo "[update] Nothing else to do."
    exit 0
fi

if [[ -f "$ROOT/VERSION" ]]; then
    NEW_VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
fi

echo "[update] Updated version: $NEW_VERSION"

section "Pull latest Docker images"

(
    cd "$ROOT/web"
    docker compose --env-file "$RI_CONF_ENV" pull
)

section "Restart Recursive-IR Docker web stack"

(
    cd "$ROOT/web"
    docker compose --env-file "$RI_CONF_ENV" up -d
)

section "Reload systemd"

systemctl daemon-reload

for unit in \
    dfir-worker.service \
    dfir-watcher.service \
    dfir-parser.timer \
    dfir-enricher.timer
do
    if systemctl list-unit-files "$unit" >/dev/null 2>&1; then
        echo "[update] Restarting $unit"
        systemctl restart "$unit" || \
            echo "[update] WARNING: Failed to restart $unit"
    fi
done


section "Docker status"

docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}' \
    | grep -E 'recursive-ir|NAMES' || true

echo
echo "[update] Recursive-IR update complete."

if [[ "$OLD_VERSION" == "$NEW_VERSION" ]]; then
    echo "[update] Version: $NEW_VERSION"
    echo "[update] Repository updated (no version change)"
else
    echo "[update] Version: $OLD_VERSION -> $NEW_VERSION"
fi

echo
echo "[update] Restarted:"
echo "  - dfir-worker"
echo "  - dfir-watcher"
echo "  - dfir-parser"
echo "  - dfir-enricher"
echo
