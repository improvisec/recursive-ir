#!/usr/bin/env python3
"""
nginx_to_jsonl.py

DFIR-friendly Nginx log -> JSONL converter.

Auto-detects mode from input filename:
  - if basename contains "access"  => parse as Nginx access log (built-in combined)
  - if basename contains "error"   => parse as Nginx error log (standard error_log)
  - otherwise: fall back to content-based sniffing (first non-empty line)

Usage (fits dfir-ingest-parse {in} {out}):
  nginx_to_jsonl.py <infile> <outfile>

Behavior:
  - Streaming conversion to JSONL
  - Unparseable lines are preserved with parse_ok=false and raw line
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime

# -----------------------------
# Access log: built-in "combined"
# -----------------------------
# $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
ACCESS_COMBINED_RE = re.compile(
    r'^(?P<remote_addr>\S+)\s+\S+\s+(?P<remote_user>\S+)\s+\[(?P<time_local>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3}|-)\s+(?P<body_bytes_sent>\d+|-)\s+'
    r'"(?P<http_referer>[^"]*)"\s+"(?P<http_user_agent>[^"]*)"\s*$'
)

REQ_LINE_RE = re.compile(r'^(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<proto>HTTP/\d(?:\.\d)?)$')
TIME_LOCAL_FMT = "%d/%b/%Y:%H:%M:%S %z"


def _int_or_none(v: str):
    if v in (None, "", "-"):
        return None
    try:
        return int(v)
    except ValueError:
        return None


def _parse_time_local_iso(s: str):
    if not s:
        return None
    try:
        return datetime.strptime(s, TIME_LOCAL_FMT).isoformat()
    except Exception:
        return None


def _null_if_dash(x):
    return None if x in (None, "", "-") else x


def parse_access_line(line: str) -> dict:
    raw = line.rstrip("\n")
    m = ACCESS_COMBINED_RE.match(raw)
    if not m:
        return {
            "parse_ok": False,
            "log_type": "nginx_access",
            "log_format": "combined",
            "raw": raw,
        }

    d = m.groupdict()
    req = (d.get("request") or "").strip()
    rm = REQ_LINE_RE.match(req)

    return {
        "parse_ok": True,
        "log_type": "nginx_access",
        "log_format": "combined",
        "remote_addr": d.get("remote_addr"),
        "remote_user": _null_if_dash(d.get("remote_user")),
        "time_local": d.get("time_local"),
        "timestamp": _parse_time_local_iso(d.get("time_local") or ""),
        "request": req if req else None,
        "request_method": rm.group("method") if rm else None,
        "request_path": rm.group("path") if rm else None,
        "request_protocol": rm.group("proto") if rm else None,
        "status": _int_or_none(d.get("status")),
        "body_bytes_sent": _int_or_none(d.get("body_bytes_sent")),
        "http_referer": _null_if_dash(d.get("http_referer")),
        "http_user_agent": _null_if_dash(d.get("http_user_agent")),
        "parse_confidence": "builtin_combined",
    }


# -----------------------------
# Error log: standard nginx error_log
# -----------------------------
ERROR_PREFIX_RE = re.compile(
    r'^(?P<date>\d{4}/\d{2}/\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'\[(?P<level>[a-zA-Z]+)\]\s+'
    r'(?P<pid>\d+)#(?P<tid>\d+):\s+\*(?P<conn>\d+)\s+'
    r'(?P<rest>.*)$'
)

# Often present (not guaranteed) after message, in tail key:value fragments:
ERROR_KNOWN_KEYS = ["client", "server", "request", "upstream", "host", "referrer"]


def _strip_quotes(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return s[1:-1]
    return s


def _parse_error_tail(rest: str):
    """
    Split error log 'rest' into:
      - message (free-form)
      - kv map for known keys
    Peel from RIGHT to avoid commas inside message and quoted strings.
    """
    kv = {}
    working = rest

    for key in reversed(ERROR_KNOWN_KEYS):
        marker = f", {key}:"
        idx = working.rfind(marker)
        if idx == -1:
            continue
        value_part = working[idx + len(marker):].strip()
        kv[key] = _strip_quotes(value_part)
        working = working[:idx]

    message = working.strip()
    if message.endswith(","):
        message = message[:-1].rstrip()

    return message, kv


def _parse_error_timestamp_iso(date_s: str, time_s: str):
    # error_log does not include tz; keep naive ISO
    try:
        dt = datetime.strptime(f"{date_s} {time_s}", "%Y/%m/%d %H:%M:%S")
        return dt.strftime("%Y-%m-%dT%H:%M:%S")
    except Exception:
        return None


def parse_error_line(line: str) -> dict:
    raw = line.rstrip("\n")
    m = ERROR_PREFIX_RE.match(raw)
    if not m:
        return {
            "parse_ok": False,
            "log_type": "nginx_error",
            "raw": raw,
        }

    d = m.groupdict()
    message, kv = _parse_error_tail(d.get("rest") or "")

    request = kv.get("request")
    req_method = req_path = req_proto = None
    if request:
        rm = REQ_LINE_RE.match(request.strip())
        if rm:
            req_method, req_path, req_proto = rm.group("method"), rm.group("path"), rm.group("proto")

    return {
        "parse_ok": True,
        "log_type": "nginx_error",
        "timestamp": _parse_error_timestamp_iso(d.get("date") or "", d.get("time") or ""),
        "level": (d.get("level") or "").lower() or None,
        "pid": _int_or_none(d.get("pid")),
        "tid": _int_or_none(d.get("tid")),
        "connection_id": _int_or_none(d.get("conn")),
        "error_message": message if message else None,
        "remote_addr": kv.get("client"),
        "nginx_server": kv.get("server"),
        "request": request,
        "request_method": req_method,
        "request_path": req_path,
        "request_protocol": req_proto,
        "upstream": kv.get("upstream"),
        "host": kv.get("host"),
        "referrer": kv.get("referrer"),
        "parse_confidence": "nginx_error_prefix",
    }


# -----------------------------
# Auto-detect
# -----------------------------
def detect_mode(infile: str) -> str:
    """
    Returns "access" or "error".
    Priority:
      1) filename contains access/error (case-insensitive)
      2) sniff first non-empty line content
      3) default to access
    """
    base = os.path.basename(infile).lower()
    if "access" in base:
        return "access"
    if "error" in base:
        return "error"

    # content sniff
    try:
        with open(infile, "r", encoding="utf-8", errors="replace") as f:
            for _ in range(200):  # scan a bit
                line = f.readline()
                if not line:
                    break
                s = line.strip()
                if not s:
                    continue
                if ERROR_PREFIX_RE.match(s):
                    return "error"
                if ACCESS_COMBINED_RE.match(s):
                    return "access"
                # if it looks like error timestamp prefix even without pid/tid, bias error
                if re.match(r'^\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\s+\[', s):
                    return "error"
    except Exception:
        pass

    return "access"


def main():
    ap = argparse.ArgumentParser(description="Convert Nginx access/error logs to JSONL (auto-detect mode).")
    ap.add_argument("infile", help="Input log file path")
    ap.add_argument("outfile", help="Output JSONL file path")
    ap.add_argument("--include-raw", action="store_true", help="Include raw line for parse_ok=true records as well")
    ap.add_argument("--force-access", action="store_true", help="Override auto-detect: force access mode")
    ap.add_argument("--force-error", action="store_true", help="Override auto-detect: force error mode")
    args = ap.parse_args()

    if args.force_access and args.force_error:
        print("ERROR: cannot use both --force-access and --force-error", file=sys.stderr)
        return 2

    if args.force_access:
        mode = "access"
    elif args.force_error:
        mode = "error"
    else:
        mode = detect_mode(args.infile)

    parse_fn = parse_access_line if mode == "access" else parse_error_line

    try:
        fin = open(args.infile, "r", encoding="utf-8", errors="replace")
    except Exception as e:
        print(f"ERROR: cannot open infile: {e}", file=sys.stderr)
        return 2

    try:
        fout = open(args.outfile, "w", encoding="utf-8")
    except Exception as e:
        print(f"ERROR: cannot open outfile: {e}", file=sys.stderr)
        fin.close()
        return 2

    n = 0
    bad = 0

    for line in fin:
        n += 1
        obj = parse_fn(line)

        if args.include_raw and obj.get("parse_ok") and "raw" not in obj:
            obj["raw"] = line.rstrip("\n")

        if not obj.get("parse_ok"):
            bad += 1

        fout.write(json.dumps(obj, ensure_ascii=False) + "\n")

    fin.close()
    fout.close()

    print(f"nginx_to_jsonl: mode={mode} lines={n} bad={bad}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
