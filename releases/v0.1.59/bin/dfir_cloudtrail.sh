#!/usr/bin/env bash
set -euo pipefail

in="$1"
out="$2"

mkdir -p "$(dirname "$out")"
: > "$out"

emit_records_from_file() {
  local f="$1"

  if [[ "$f" == *.gz ]]; then
    gzip -dc -- "$f" \
      | jq -c 'select((.Records? | type) == "array") | .Records[]?' \
      >> "$out" 2>/dev/null || true
  else
    jq -c 'select((.Records? | type) == "array") | .Records[]?' -- "$f" \
      >> "$out" 2>/dev/null || true
  fi
}

if [[ -d "$in" ]]; then
  while IFS= read -r -d '' f; do
    emit_records_from_file "$f"
  done < <(find "$in" -type f \( -name '*CloudTrail_*.json.gz' -o -name '*CloudTrail_*.json' \) -print0)
else
  emit_records_from_file "$in"
fi
