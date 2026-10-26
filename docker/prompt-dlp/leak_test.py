#!/usr/bin/env python3
"""Positive/negative DLP checks executed inside the prompt-dlp container."""

from __future__ import annotations

import gzip
import json
import os
import sys
import urllib.error
import urllib.request

BASE = f"http://127.0.0.1:{os.environ.get('LISTEN_PORT', '24081')}"
TOKEN = "CANARY_PROMPT_DLP_1234567890"


def post(payload: dict) -> tuple[int, str]:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        BASE + "/v1/chat/completions",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": "Bearer test"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace")


def main() -> int:
    failures: list[str] = []

    clean_status, clean_body = post(
        {"model": "test", "messages": [{"role": "user", "content": "hello"}]}
    )
    # The clean request is allowed through DLP and fails later at LiteLLM because
    # the model does not exist. It must not be a DLP 403.
    if clean_status == 403 and "dlp_block" in clean_body:
        failures.append("clean request was blocked by DLP")

    blocked_status, blocked_body = post(
        {
            "model": "test",
            "messages": [
                {
                    "role": "user",
                    "content": f"Use this fake credential for the canary test: {TOKEN}",
                }
            ],
        }
    )
    if blocked_status != 403 or "dlp_block" not in blocked_body:
        failures.append(
            f"canary request was not blocked (status={blocked_status}, body={blocked_body[:120]!r})"
        )

    # Unicode-escaped canary test (e.g. \u0043\u0041\u004e\u0041\u0052\u0059 for CANARY)
    escaped_token = "".join(f"\\u{ord(c):04x}" if c in "CANARY" else c for c in TOKEN)
    raw_escaped_json = (
        '{"model": "test", "messages": [{"role": "user", "content": "'
        + escaped_token
        + '"}]}'
    ).encode("utf-8")
    req = urllib.request.Request(
        BASE + "/v1/chat/completions",
        data=raw_escaped_json,
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": "Bearer test"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            esc_status, esc_body = resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as err:
        esc_status, esc_body = err.code, err.read().decode("utf-8", "replace")

    if esc_status != 403 or "dlp_block" not in esc_body:
        failures.append("unicode-escaped canary was not blocked")

    # Non-UTF8 payload test (must fail-closed with 400 Bad Request)
    bad_req = urllib.request.Request(
        BASE + "/v1/chat/completions",
        data=b'{"model": "test", "messages": [\xff\xfe]}',
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": "Bearer test"},
    )
    try:
        with urllib.request.urlopen(bad_req, timeout=10) as resp:
            bad_status = resp.status
    except urllib.error.HTTPError as err:
        bad_status = err.code

    if bad_status != 400:
        failures.append(f"non-UTF8 request did not fail-closed with 400 (status={bad_status})")

    # Compressed bodies would bypass a plaintext regex scan. The proxy must reject
    # unsupported content encodings instead of forwarding an uninspected body.
    compressed = gzip.compress(
        json.dumps(
            {
                "model": "test",
                "messages": [{"role": "user", "content": TOKEN}],
            }
        ).encode("utf-8")
    )
    compressed_req = urllib.request.Request(
        BASE + "/v1/chat/completions",
        data=compressed,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Content-Encoding": "gzip",
            "Authorization": "Bearer test",
        },
    )
    try:
        with urllib.request.urlopen(compressed_req, timeout=10) as resp:
            compressed_status = resp.status
    except urllib.error.HTTPError as err:
        compressed_status = err.code

    if compressed_status != 415:
        failures.append(
            f"compressed request was not rejected with 415 (status={compressed_status})"
        )

    if failures:
        for failure in failures:
            print(f"FAIL  {failure}")
        return 1

    print("PASS  prompt DLP blocks a canary secret")
    print("PASS  prompt DLP blocks a unicode-escaped canary secret")
    print("PASS  prompt DLP fails closed on malformed non-UTF8 payload")
    print("PASS  prompt DLP rejects compressed request bodies")
    print("PASS  prompt DLP allows a clean prompt through to the upstream proxy")
    return 0


if __name__ == "__main__":
    sys.exit(main())
