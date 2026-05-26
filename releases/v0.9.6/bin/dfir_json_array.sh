#!/usr/bin/env bash
# ------------------------------------------------------------------
# Recursive-IR helper script
# Copyright (c) 2026 Mark Jayson Alvarez
# Licensed under the Recursive-IR License
# ------------------------------------------------------------------
set -euo pipefail

in="$1"
out="$2"

mkdir -p "$(dirname "$out")"

# For a JSON file whose top-level is an array, output JSONL:
# one object per line.
jq -c '.[]' "$in" > "$out"

