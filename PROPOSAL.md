# Repository proposal

**Repository name:** `ssh-auth-log-summary`

**One-line description:** A read-only Python 3.10+ CLI that counts repeated failed SSH password attempts by source IP in a user-supplied local Linux authentication log.

**GitHub topics (exact):** `python`, `linux`, `ssh`, `log-analysis`, `cybersecurity`, `cli`, `beginner-friendly`

## Scope and safety

This small, local-only learning project parses familiar `sshd` “Failed password” log lines and groups them by source IP. It reads but never changes a user-selected file. It does not scan networks, block addresses, claim to detect compromise, or upload/share logs. Documentation and tests use documentation-only example IP addresses; users should not publish real authentication logs.

## Proposed files

- `ssh_auth_log_summary.py` — standard-library CLI and parsing/reporting functions.
- `sample_auth.log` — synthetic example input.
- `test_ssh_auth_log_summary.py` — `unittest` coverage of matching, exclusions, thresholds, ordering, IPv4/IPv6, and CLI errors.
- `README.md` — beginner-oriented usage, explanation, privacy guidance, limitations, and next steps.

## Dependencies and usage

Python 3.10 or newer; Python standard library only. Run directly with `python3 ssh_auth_log_summary.py PATH` and test with `python3 -m unittest -v`.
