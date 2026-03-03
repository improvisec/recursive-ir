#!/usr/bin/env bash
set -euo pipefail

IN="${1:?missing input}"
OUT="${2:?missing output}"

mkdir -p "$(dirname "$OUT")"

# If input is gzipped, decompress; else copy.
case "$IN" in
  *.gz) gzip -cd -- "$IN" > "$OUT" ;;
  *)    cat -- "$IN" > "$OUT" ;;
esac
