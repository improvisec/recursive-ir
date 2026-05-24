#!/usr/bin/env python3
# ------------------------------------------------------------------
# Recursive-IR helper script
# Copyright (c) 2026 Mark Jayson Alvarez
# Licensed under the Recursive-IR License
# ------------------------------------------------------------------

import argparse
import csv
import json
import os
import sys


def non_blank_row(row):
    return any((cell or "").strip() for cell in row)


def emit_records_from_file(src, out_fh, header_arg):
    try:
        with open(src, "r", encoding="utf-8-sig", newline="") as fh:
            reader = csv.reader(fh)

            headers = None

            if header_arg:
                headers = [
                    h.strip()
                    for h in header_arg.split(",")
                    if h.strip()
                ]
            else:
                for row in reader:
                    if non_blank_row(row):
                        headers = [
                            (cell or "").strip()
                            for cell in row
                        ]
                        break

            if not headers:
                return

            for row in reader:
                if not non_blank_row(row):
                    continue

                record = {}

                for idx, value in enumerate(row):
                    if idx < len(headers) and headers[idx]:
                        name = headers[idx]
                    else:
                        name = f"unknown_column_{idx - len(headers) + 1}"

                    record[name] = value

                out_fh.write(
                    json.dumps(
                        record,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
                )
                out_fh.write("\n")

    except Exception:
        return


def iter_csv_files(path):
    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for name in files:
                if name.lower().endswith(".csv"):
                    yield os.path.join(root, name)
    else:
        yield path


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--column-headers",
        help="Comma-separated column headers for headerless CSV files",
    )

    parser.add_argument("input")
    parser.add_argument("output")

    args = parser.parse_args()

    os.makedirs(
        os.path.dirname(os.path.abspath(args.output)),
        exist_ok=True,
    )

    with open(args.output, "w", encoding="utf-8") as out_fh:
        for path in iter_csv_files(args.input):
            emit_records_from_file(
                path,
                out_fh,
                args.column_headers,
            )


if __name__ == "__main__":
    main()
