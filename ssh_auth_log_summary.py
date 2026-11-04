#!/usr/bin/env python3
"""Read-only summary of repeated failed SSH password log entries."""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Iterable

# Match the sshd message payload; syslog prefixes are intentionally ignored.
FAILED_PASSWORD = re.compile(
    r"\bsshd(?:\[\d+\])?:\s+Failed password for (?:invalid user )?\S+\s+"
    r"from\s+(\S+)\s+port\s+\d+\s+ssh2\b"
)


def matching_addresses(lines: Iterable[str]) -> Counter[str]:
    """Count valid source IP addresses in failed-password sshd messages."""
    counts: Counter[str] = Counter()
    for line in lines:
        match = FAILED_PASSWORD.search(line)
        if not match:
            continue
        try:
            address = ipaddress.ip_address(match.group(1))
        except ValueError:
            continue
        counts[str(address)] += 1
    return counts


def summarize(path: Path, threshold: int = 2, limit: int | None = None) -> list[tuple[str, int]]:
    """Read a UTF-8 log file and return qualifying (address, count) pairs."""
    with path.open("r", encoding="utf-8", errors="replace") as log_file:
        counts = matching_addresses(log_file)
    rows = [(address, count) for address, count in counts.items() if count >= threshold]
    rows.sort(key=lambda row: (-row[1], row[0]))
    return rows if limit is None else rows[:limit]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Count repeated failed SSH password entries in a local log (read-only)."
    )
    parser.add_argument("logfile", type=Path, help="path to a local Linux authentication log")
    parser.add_argument("--threshold", type=int, default=2, help="minimum count per address (default: 2)")
    parser.add_argument("--limit", type=int, help="maximum number of addresses to display")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.threshold < 1:
        parser.error("--threshold must be at least 1")
    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be at least 1")
    try:
        rows = summarize(args.logfile, args.threshold, args.limit)
    except OSError as exc:
        parser.error(f"cannot read {args.logfile}: {exc.strerror or exc}")
    except UnicodeError as exc:
        parser.error(f"cannot decode {args.logfile}: {exc}")

    print(f"Failed SSH password attempts (threshold: {args.threshold})")
    if not rows:
        print("No addresses met the threshold.")
    else:
        for address, count in rows:
            print(f"{address:<39} {count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
