#!/usr/bin/env python3
"""Host-side admin CLI, executed inside the broker container with docker exec."""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = f"http://127.0.0.1:{os.environ.get('ADMIN_PORT', '24900')}"


def sanitize_terminal(text: str) -> str:
    """Strip ANSI escapes and escape every control character.

    Newlines and tabs must be escaped too: an attacker-controlled URL or body
    preview containing a newline could otherwise forge extra ``id:``/``url:``
    lines in the operator's terminal. The preview is intentionally one line.
    """
    cleaned = re.sub(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])", "", text)
    return "".join(
        c if 32 <= ord(c) <= 126 else f"\\x{ord(c):02x}" for c in cleaned
    )


def request(path: str, method: str = "GET") -> tuple[int, dict]:
    req = urllib.request.Request(BASE + path, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        try:
            payload = json.loads(error.read().decode("utf-8"))
        except Exception:  # noqa: BLE001
            payload = {"error": str(error)}
        return error.code, payload


def list_pending() -> int:
    status, payload = request("/pending")
    if status != 200:
        print(f"error: {payload}", file=sys.stderr)
        return 1
    pending = payload.get("pending", [])
    if not pending:
        print("No pending egress requests.")
        return 0
    for item in pending:
        req_id = sanitize_terminal(str(item.get("id", "")))
        method = sanitize_terminal(str(item.get("method", "")))
        url = sanitize_terminal(str(item.get("url", "")))
        body_bytes = item.get("body_bytes", 0)
        body_sha = sanitize_terminal(str(item.get("body_sha256", "")))
        truncated = item.get("truncated", False)

        print(f"id:      {req_id}")
        print(f"method:  {method}")
        print(f"url:     {url}")
        print(f"payload: {body_bytes} bytes (SHA-256: {body_sha[:16]}...)")
        print("body:")
        preview = item.get("body_preview", "")
        if preview:
            print(sanitize_terminal(preview))
            if truncated:
                print(f"  [TRUNCATED: previewing 2000 of {body_bytes} bytes. Full SHA-256: {body_sha}]")
        else:
            print("  <empty>")
        print("-" * 72)
    print("Approve with: bin/egress-approve <id>")
    print("Deny with:    bin/egress-deny <id>")
    return 0


def decide(action: str, request_id: str) -> int:
    status, payload = request(
        f"/{action}/{urllib.parse.quote(request_id, safe='')}", method="POST"
    )
    if status != 200:
        print(f"error: {payload}", file=sys.stderr)
        return 1
    print(f"{action}: {sanitize_terminal(request_id)}")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: admin.py list|approve <id>|deny <id>|health", file=sys.stderr)
        return 2
    command = argv[1].lower()
    if command == "list":
        return list_pending()
    if command in {"approve", "deny"}:
        if len(argv) != 3:
            print(f"usage: admin.py {command} <id>", file=sys.stderr)
            return 2
        return decide(command, argv[2])
    if command == "health":
        status, payload = request("/health")
        print(json.dumps(payload, indent=2))
        return 0 if status == 200 else 1
    print(f"unknown command: {command}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
