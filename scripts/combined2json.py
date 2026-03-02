#!/usr/bin/env python3
"""
combined2json.py

Parse Apache / Nginx Combined Log Format into JSON Lines.

Combined format:
  %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"

Supports:
- combined2json.py input.log output.jsonl
- cat access.log | combined2json.py
"""

import re
import sys
import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any

COMBINED_RE = re.compile(
    r'^(?P<remote_addr>\S+)\s+'
    r'(?P<remote_logname>\S+)\s+'
    r'(?P<remote_user>\S+)\s+'
    r'\[(?P<timestamp_raw>[^\]]+)\]\s+'
    r'"(?P<request_raw>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<body_bytes_sent>\S+)\s+'
    r'"(?P<http_referer>[^"]*)"\s+'
    r'"(?P<http_user_agent>[^"]*)"\s*$'
)

REQUEST_RE = re.compile(
    r'^(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<protocol>HTTP/\d\.\d)$'
)

def dash_to_none(v: str) -> Optional[str]:
    return None if v == "-" else v

def parse_int(v: str) -> Optional[int]:
    if v == "-" or v == "":
        return None
    try:
        return int(v)
    except ValueError:
        return None

def parse_time(s: str) -> Optional[str]:
    try:
        dt = datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z")
        return dt.isoformat()
    except Exception:
        return None

def parse_line(line: str) -> Optional[Dict[str, Any]]:
    m = COMBINED_RE.match(line.rstrip("\n"))
    if not m:
        return None

    d = m.groupdict()

    # Normalize dash fields
    d["remote_logname"] = dash_to_none(d["remote_logname"])
    d["remote_user"] = dash_to_none(d["remote_user"])
    d["http_referer"] = dash_to_none(d["http_referer"])
    d["http_user_agent"] = dash_to_none(d["http_user_agent"])

    # Numbers
    d["status"] = parse_int(d["status"])
    d["body_bytes_sent"] = parse_int(d["body_bytes_sent"])

    # Timestamp
    d["timestamp"] = parse_time(d["timestamp_raw"])

    # Request parsing
    req = dash_to_none(d["request_raw"])
    d["request"] = req

    d["request_method"] = None
    d["request_path"] = None
    d["request_protocol"] = None

    if req:
        rm = REQUEST_RE.match(req)
        if rm:
            d["request_method"] = rm.group("method")
            d["request_path"] = rm.group("path")
            d["request_protocol"] = rm.group("protocol")

    return d

def main() -> int:
    # dfir mode: combined2json.py IN OUT
    if len(sys.argv) == 3:
        infile = sys.argv[1]
        outfile = sys.argv[2]
        fin = open(infile, "r", encoding="utf-8", errors="replace")
        fout = open(outfile, "w", encoding="utf-8")
    # stdin -> stdout
    elif len(sys.argv) == 1:
        fin = sys.stdin
        fout = sys.stdout
    else:
        print("usage: combined2json.py [input output]", file=sys.stderr)
        return 2

    total = 0
    failed = 0

    for line in fin:
        total += 1
        if not line.strip():
            continue
        obj = parse_line(line)
        if obj is None:
            failed += 1
            continue
        fout.write(json.dumps(obj, ensure_ascii=False) + "\n")

    if fin is not sys.stdin:
        fin.close()
    if fout is not sys.stdout:
        fout.close()

    print(
        f"combined2json: parsed={total - failed} failed={failed} total={total}",
        file=sys.stderr
    )

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
