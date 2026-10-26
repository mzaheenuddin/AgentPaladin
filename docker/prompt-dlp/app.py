#!/usr/bin/env python3
"""Prompt DLP proxy.

Scans JSON request bodies for secret-like values before forwarding them to
LiteLLM. This is a guardrail against accidental leaks, not a boundary against
a determined agent that encodes or splits data.
"""

from __future__ import annotations

import http.client
import json
import os
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from dlp_patterns import Finding, redact_text, scan_text

UPSTREAM_URL = os.environ.get("UPSTREAM_URL", "http://llm-proxy:24000")
DLP_ACTION = os.environ.get("DLP_ACTION", "block").lower()
MAX_BODY_BYTES = int(os.environ.get("MAX_BODY_BYTES", str(32 * 1024 * 1024)))
TIMEOUT_SECONDS = int(os.environ.get("UPSTREAM_TIMEOUT_SECONDS", "900"))
REQUEST_TIMEOUT_SECONDS = int(os.environ.get("REQUEST_TIMEOUT_SECONDS", "30"))
HOST = os.environ.get("LISTEN_HOST", "0.0.0.0")
PORT = int(os.environ.get("LISTEN_PORT", "24081"))
UNSUPPORTED_ENCODINGS = {"gzip", "x-gzip", "deflate", "br", "compress", "zstd"}
BLOCKED_FORWARD_HEADERS = {
    "cookie",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "via",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
}

_UPSTREAM = urllib.parse.urlparse(UPSTREAM_URL)


def log(event: str, **fields: Any) -> None:
    payload = {"event": event, **fields}
    print(json.dumps(payload, separators=(",", ":")), flush=True)


def scan_payload(body: bytes) -> tuple[bool, list[Finding]]:
    """Scan payload for secrets. Returns (is_valid_utf8, findings)."""
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return False, []

    findings = list(scan_text(text))

    # Also parse JSON to inspect unescaped unicode strings (e.g. \u0041\u004b...)
    try:
        data = json.loads(text)

        def _extract_strings(val: Any) -> list[str]:
            res: list[str] = []
            if isinstance(val, str):
                res.append(val)
            elif isinstance(val, list):
                for item in val:
                    res.extend(_extract_strings(item))
            elif isinstance(val, dict):
                for k, v in val.items():
                    res.append(str(k))
                    res.extend(_extract_strings(v))
            return res

        extracted = _extract_strings(data)
        seen_rules = {f.rule for f in findings}
        for item in extracted:
            for sub_finding in scan_text(item):
                if sub_finding.rule not in seen_rules:
                    seen_rules.add(sub_finding.rule)
                    findings.append(sub_finding)
    except Exception:
        pass

    return True, findings


def redact_json(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_json(item) for item in value]
    if isinstance(value, dict):
        return {
            redact_text(str(key)): redact_json(item) for key, item in value.items()
        }
    return value


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = REQUEST_TIMEOUT_SECONDS

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        # Suppress BaseHTTPRequestHandler's default request line logging. It can
        # include URLs; our own logs intentionally omit query strings.
        return

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

    def _read_body(self) -> bytes | None:
        length_header = self.headers.get("Content-Length")
        if length_header is None:
            return b""
        try:
            length = int(length_header)
        except ValueError:
            self._send_json(400, {"error": {"message": "invalid Content-Length"}})
            return None
        if length < 0 or length > MAX_BODY_BYTES:
            self._send_json(413, {"error": {"message": "request body too large"}})
            return None
        return self.rfile.read(length)

    def _forward(self, method: str, body: bytes) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        upstream_path = parsed.path
        if parsed.query:
            upstream_path += "?" + parsed.query

        headers: dict[str, str] = {}
        for key, value in self.headers.items():
            lower = key.lower()
            if lower in {"host", "content-length", "connection", "transfer-encoding"}:
                continue
            if lower in BLOCKED_FORWARD_HEADERS:
                continue
            headers[key] = value
        headers["Host"] = _UPSTREAM.netloc
        if body:
            headers["Content-Length"] = str(len(body))

        connection = http.client.HTTPConnection(
            _UPSTREAM.hostname or "llm-proxy",
            _UPSTREAM.port or 80,
            timeout=TIMEOUT_SECONDS,
        )
        try:
            connection.request(method, upstream_path, body=body or None, headers=headers)
            response = connection.getresponse()
        except Exception as exc:  # noqa: BLE001
            log("upstream_error", error=type(exc).__name__)
            self._send_json(502, {"error": {"message": "LLM proxy unavailable"}})
            connection.close()
            return

        try:
            self.send_response(response.status)
            for key, value in response.getheaders():
                lower = key.lower()
                if lower in {"transfer-encoding", "connection", "content-length"}:
                    continue
                self.send_header(key, value)
            self.send_header("Connection", "close")
            self.end_headers()

            while True:
                chunk = response.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            response.close()
            connection.close()

        log(
            "proxied",
            method=method,
            path=parsed.path,
            status=getattr(response, "status", 0),
        )

    def do_GET(self) -> None:  # noqa: N802
        if self.path.split("?", 1)[0] == "/health":
            self._send_json(200, {"status": "ok"})
            return
        self._forward("GET", b"")

    def do_POST(self) -> None:  # noqa: N802
        transfer_encoding = self.headers.get("Transfer-Encoding", "").strip().lower()
        if transfer_encoding and transfer_encoding != "identity":
            log("prompt_dlp_encoding_error", path=self.path.split("?", 1)[0])
            self._send_json(
                415,
                {
                    "error": {
                        "message": "Unsupported Transfer-Encoding",
                        "type": "invalid_request_error",
                    }
                },
            )
            return
        content_encoding = self.headers.get("Content-Encoding", "identity").strip().lower()
        if content_encoding in UNSUPPORTED_ENCODINGS or content_encoding not in {
            "",
            "identity",
        }:
            log("prompt_dlp_encoding_error", path=self.path.split("?", 1)[0])
            self._send_json(
                415,
                {
                    "error": {
                        "message": "Compressed request bodies are not inspected and are rejected",
                        "type": "invalid_request_error",
                    }
                },
            )
            return
        if self.headers.get("Content-Length") is None:
            self._send_json(
                411,
                {
                    "error": {
                        "message": "Content-Length is required",
                        "type": "invalid_request_error",
                    }
                },
            )
            return
        body = self._read_body()
        if body is None:
            return

        valid_utf8, findings = scan_payload(body)
        if not valid_utf8:
            log("prompt_dlp_encoding_error", path=self.path.split("?", 1)[0])
            self._send_json(
                400,
                {
                    "error": {
                        "message": "Malformed request: body must be valid UTF-8",
                        "type": "invalid_request_error",
                    }
                },
            )
            return

        if findings:
            rules = sorted({finding.rule for finding in findings})
            log("prompt_dlp_block", path=self.path.split("?", 1)[0], rules=rules)
            if DLP_ACTION == "redact":
                try:
                    payload = json.loads(body.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    self._send_json(
                        403,
                        {
                            "error": {
                                "message": "Blocked by prompt DLP: potential secret detected",
                                "type": "dlp_block",
                            }
                        },
                    )
                    return
                body = json.dumps(redact_json(payload), separators=(",", ":")).encode("utf-8")
            else:
                self._send_json(
                    403,
                    {
                        "error": {
                            "message": "Blocked by prompt DLP: potential secret detected",
                            "type": "dlp_block",
                        }
                    },
                )
                return

        self._forward("POST", body)


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    log("starting", listen=f"{HOST}:{PORT}", upstream=UPSTREAM_URL, action=DLP_ACTION)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
