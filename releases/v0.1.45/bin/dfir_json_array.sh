#!/usr/bin/env bash
set -euo pipefail

in="$1"
out="$2"

mkdir -p "$(dirname "$out")"

# For a JSON file whose top-level is an array, output JSONL:
# one object per line.
jq -c '.[]' "$in" > "$out"

