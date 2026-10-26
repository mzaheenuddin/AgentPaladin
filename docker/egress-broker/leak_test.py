#!/usr/bin/env python3
"""Unit checks for the broker's DLP and target-validation helpers."""

from __future__ import annotations

import sys

from app import _host_matches, _is_public_ip, _sanitize_headers
from dlp_patterns import scan_text


def main() -> int:
    failures: list[str] = []

    canary = "CANARY_EGRESS_BROKER_1234567890"
    if not scan_text(canary):
        failures.append("canary token was not detected")

    if not scan_text("postgres://user:supersecretpassword@db.example.com/app"):
        failures.append("database URL with password was not detected")

    if not _host_matches("api.github.com", ["api.github.com"]):
        failures.append("exact host allowlist match failed")

    if not _host_matches("api.github.com", [".github.com"]):
        failures.append("suffix host allowlist match failed")

    if _host_matches("evilgithub.com", [".github.com"]):
        failures.append("suffix allowlist matched an unrelated suffix")

    if _is_public_ip("127.0.0.1") or _is_public_ip("10.0.0.1") or _is_public_ip("169.254.169.254"):
        failures.append("private address classification failed")

    if not _is_public_ip("1.1.1.1"):
        failures.append("public address classification failed")

    sanitized = _sanitize_headers(
        {
            "User-Agent": "agent-paladin-test",
            "Authorization": "Bearer should-not-pass",
            "X-Api-Key": "should-not-pass",
            "X-Custom": "should-not-pass",
            "Content-Encoding": "gzip",
        }
    )
    if sanitized.get("User-Agent") != "agent-paladin-test":
        failures.append("safe request header was dropped")
    if any(
        key.lower()
        in {"authorization", "x-api-key", "x-custom", "content-encoding"}
        for key in sanitized
    ):
        failures.append("unsafe request header was forwarded")

    from admin import sanitize_terminal

    tainted = "https://safe.com\x1b[2K\rhttps://spoofed.evil.com\nid: forged"
    clean = sanitize_terminal(tainted)
    if "\x1b" in clean or "\r" in clean or "\n" in clean:
        failures.append("terminal escape sanitization failed")

    if failures:
        for failure in failures:
            print(f"FAIL  {failure}")
        return 1
    print("PASS  broker DLP detects canary and credential patterns")
    print("PASS  broker host matching is suffix-safe")
    print("PASS  broker rejects private, loopback, and link-local addresses")
    print("PASS  broker forwards only allowlisted request headers")
    print("PASS  admin CLI strips ANSI terminal injection sequences")
    return 0


if __name__ == "__main__":
    sys.exit(main())
