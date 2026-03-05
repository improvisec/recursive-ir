#!/usr/bin/env bash
set -euo pipefail

# --- Add venv bin directory to PATH ---
export PATH="/home/recursive/.venv/bin:$PATH"

if [ "$#" -lt 3 ]; then
  echo "Usage: $0 <function> <input_image> <output_jsonl>" >&2
  exit 1
fi

func="$1"    # e.g. evtx, prefetch, registry, amcache
in="$2"      # {in}
out="$3"     # {out}

# Example:
# target-query -f evtx -t disk.vmdk | rdump -j -w out.jsonl

target-query -f "$func" -t "$in" | rdump -J -w "$out"

