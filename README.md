# SSH Auth Log Summary

A read-only Python 3.10+ command-line tool for counting repeated failed SSH password attempts by source IP in a local Linux authentication log.

This is a small practice project for learning Python text processing and test-driven development. It is distinct from network auditors, browser utilities, and general learning logs: its one job is summarizing a narrow pattern in a file you explicitly provide.

## What it reads

The parser recognizes lines containing OpenSSH's `sshd` message form `Failed password for USER from ADDRESS port PORT ssh2`, including `invalid user USER`. It accepts IPv4 and IPv6 addresses and validates them with Python's standard-library `ipaddress` module. It ignores other events, malformed addresses, and unrelated lines. Log prefixes (such as syslog timestamps/host/process IDs) are not interpreted.

A common Linux source is `/var/log/auth.log` on Debian/Ubuntu or `/var/log/secure` on some other distributions. Access may require elevated read permissions. Prefer copying a small excerpt into a file you control rather than running the script with elevated privileges.

## Quick start

Check that Python 3.10+ is available:

```sh
python3 --version
```

From this directory, summarize the synthetic fixture:

```sh
python3 ssh_auth_log_summary.py sample_auth.log
```

Choose a minimum count (default is 2):

```sh
python3 ssh_auth_log_summary.py /path/to/auth.log --threshold 3
```

An optional `--limit N` limits how many results are displayed. Results sort by count descending, then IP address ascending for ties. A valid file with no matching addresses prints a clear message. A missing/unreadable file or invalid option produces a CLI error and nonzero exit status.

## Sample

`sample_auth.log` contains only synthetic lines and documentation-only example addresses. Running the default command gives output like:

```text
Failed SSH password attempts (threshold: 2)
198.51.100.23  3
2001:db8::7    2
```

The summary counts matching log lines per source IP; it does not infer who owns an address or what happened outside those lines.

## Tests

Run the standard-library test suite from this directory:

```sh
python3 -m unittest -v
```

Tests cover successful matches and ignored messages, threshold and stable ordering, IPv4 and IPv6 parsing, and invalid CLI arguments and file paths. No third-party packages or network access are needed.

## Limitations, safety, and privacy

**This tool is a basic text summarizer, not an intrusion-detection system or security verdict.** A count is not proof of an attack or compromise; legitimate users, automated systems, log rotation, formatting differences, and incomplete logs can affect results. It does not correlate events, inspect successful logins, identify users, or make recommendations about blocking anyone.

The program opens the supplied file for reading only and does not alter it, contact a network, or transmit data. Real authentication logs can contain personal or operational information. Keep them private, use synthetic samples when learning, and do not publish or paste real logs into public repositories, issue trackers, or chats. The included fixture uses reserved documentation addresses only.

## Possible future improvements

- Add explicit parser support and tests for additional documented sshd log formats.
- Offer a machine-readable JSON report while keeping input local.
- Add date-range summaries only after defining which timestamp formats are supported.
- Improve error messages for common permissions and encoding problems.

Future changes should preserve read-only local operation and clearly state what the output cannot establish.
