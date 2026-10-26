#!/usr/bin/env python3
"""Human-in-the-loop egress broker.

The sandbox has no generic internet route. When it needs an external API, it
posts a request here. The broker validates the target, scans the request for
secret-like values, strips client-supplied credentials, waits for a host-side
approval, injects the configured credential, and forwards the request once.

The approval API listens on loopback only. The host CLI reaches it through
`docker compose exec`, not from the sandbox.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import socket
import ssl
import sys
import threading
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from dlp_patterns import Finding, redact_text, scan_text

CONFIG_PATH = Path(os.environ.get("BROKER_CONFIG", "/etc/broker/config.json"))
LISTEN_HOST = os.environ.get("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "24443"))
ADMIN_HOST = os.environ.get("ADMIN_HOST", "127.0.0.1")
ADMIN_PORT = int(os.environ.get("ADMIN_PORT", "24900"))
MAX_REQUEST_BYTES = int(os.environ.get("MAX_REQUEST_BYTES", str(1024 * 1024)))
MAX_RESPONSE_BYTES = int(os.environ.get("MAX_RESPONSE_BYTES", str(5 * 1024 * 1024)))
UPSTREAM_TIMEOUT = int(os.environ.get("UPSTREAM_TIMEOUT", "120"))
REQUEST_TIMEOUT_SECONDS = int(os.environ.get("REQUEST_TIMEOUT_SECONDS", "30"))
MAX_PENDING_REQUESTS = int(os.environ.get("MAX_PENDING_REQUESTS", "64"))
UNSUPPORTED_ENCODINGS = {"gzip", "x-gzip", "deflate", "br", "compress", "zstd"}

HOP_BY_HOP = {
    "connection",
    "content-length",
    "host",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


def log(event: str, **fields: Any) -> None:
    print(json.dumps({"event": event, **fields}, separators=(",", ":")), flush=True)


def load_config() -> dict[str, Any]:
    try:
        with CONFIG_PATH.open("r", encoding="utf-8") as handle:
            config = json.load(handle)
    except FileNotFoundError:
        config = {}
    except json.JSONDecodeError as exc:
        raise SystemExit(f"broker config is invalid JSON: {exc}") from exc

    config.setdefault("approvable_domains", [])
    config.setdefault("approval_required", True)
    config.setdefault("approval_timeout_seconds", 300)
    config.setdefault("allowed_methods", ["GET", "POST", "PUT", "PATCH", "DELETE"])
    config.setdefault("allowed_ports", [443])
    config.setdefault("auto_approve_domains", [])
    config.setdefault("allowed_request_headers", ["accept", "content-type", "user-agent"])
    config.setdefault("blocked_request_headers", [])
    config.setdefault("credentials", {})
    config["max_request_bytes"] = int(
        config.get("max_request_bytes", MAX_REQUEST_BYTES)
    )
    config["max_response_bytes"] = int(
        config.get("max_response_bytes", MAX_RESPONSE_BYTES)
    )
    config["approval_timeout_seconds"] = int(config["approval_timeout_seconds"])
    config["max_pending_requests"] = int(
        config.get("max_pending_requests", MAX_PENDING_REQUESTS)
    )
    config["request_timeout_seconds"] = int(
        config.get("request_timeout_seconds", REQUEST_TIMEOUT_SECONDS)
    )
    if config["approval_timeout_seconds"] <= 0:
        raise SystemExit("broker approval_timeout_seconds must be positive")
    if config["max_request_bytes"] <= 0 or config["max_response_bytes"] <= 0:
        raise SystemExit("broker byte limits must be positive")
    if config["max_pending_requests"] <= 0:
        raise SystemExit("broker max_pending_requests must be positive")
    return config


CONFIG = load_config()
PENDING_LOCK = threading.Lock()
PENDING: dict[str, "PendingRequest"] = {}


@dataclass
class PendingRequest:
    request_id: str
    method: str
    url: str
    headers: dict[str, str]
    body: bytes
    preview: str
    dlp_rules: list[str]
    body_bytes: int = 0
    body_sha256: str = ""
    truncated: bool = False
    created: float = field(default_factory=time.time)
    event: threading.Event = field(default_factory=threading.Event)
    approved: bool = False
    denied: bool = False
    denied_reason: str = ""


def _host_matches(host: str, patterns: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for raw in patterns:
        pattern = str(raw).strip().lower().rstrip(".")
        if not pattern or pattern == "*":
            continue
        if pattern.startswith("."):
            suffix = pattern[1:]
            if host == suffix or host.endswith("." + suffix):
                return True
        elif host == pattern:
            return True
    return False


def _is_public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_global and not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def _resolve_public(host: str, port: int) -> list[str]:
    addresses: list[str] = []
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"cannot resolve target host: {exc}") from exc
    for info in infos:
        address = info[4][0]
        if not _is_public_ip(address):
            raise ValueError("target resolves to a private or non-public address")
        addresses.append(address)
    if not addresses:
        raise ValueError("target did not resolve to any address")
    return addresses


def _read_secret(path: str) -> str:
    if not path:
        return ""
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _credential_for(host: str) -> dict[str, Any]:
    credentials = CONFIG.get("credentials", {})
    if host in credentials:
        return credentials[host]
    # Allow a leading-dot suffix entry such as ".example.com".
    for key, value in credentials.items():
        if key.startswith(".") and _host_matches(host, [key]):
            return value
    return {}


def _scan_request(
    method: str, url: str, headers: dict[str, str], body: bytes
) -> list[Finding]:
    text_parts = [method, url]
    for key, value in headers.items():
        text_parts.append(f"{key}: {value}")
    try:
        text_parts.append(body.decode("utf-8"))
    except UnicodeDecodeError:
        text_parts.append(body.decode("utf-8", "replace"))
    return scan_text("\n".join(text_parts))


def _sanitize_headers(raw_headers: dict[str, Any]) -> dict[str, str]:
    allowed = {item.lower() for item in CONFIG.get("allowed_request_headers", [])}
    blocked = {item.lower() for item in CONFIG.get("blocked_request_headers", [])}
    result: dict[str, str] = {}
    for key, value in raw_headers.items():
        if not isinstance(key, str) or not isinstance(value, str):
            continue
        lower = key.lower()
        if lower in HOP_BY_HOP or lower in blocked or lower not in allowed:
            continue
        result[key] = value
    return result


def _inject_credential(host: str, headers: dict[str, str]) -> None:
    credential = _credential_for(host)
    if not credential:
        return
    path = str(credential.get("secret_file", ""))
    value = _read_secret(path)
    if not value:
        return
    header = str(credential.get("header", "Authorization"))
    prefix = str(credential.get("prefix", ""))
    headers[header] = f"{prefix}{value}"


def _forward(
    method: str, url: str, headers: dict[str, str], body: bytes
) -> tuple[int, list[tuple[str, str]], bytes]:
    target = urllib.parse.urlsplit(url)
    if target.scheme != "https":
        raise ValueError("only https upstreams are allowed")
    if target.username or target.password:
        raise ValueError("URL userinfo is not allowed")
    host = target.hostname
    if not host:
        raise ValueError("missing target host")
    port = target.port or 443
    if port not in CONFIG.get("allowed_ports", [443]):
        raise ValueError("target port is not allowed")
    if not _host_matches(host, CONFIG.get("approvable_domains", [])):
        raise ValueError("target host is not in approvable_domains")
    public_ips = _resolve_public(host, port)
    pinned_ip = public_ips[0]

    path = target.path or "/"
    if target.query:
        path += "?" + target.query

    # Pin socket to the verified public IP address to eliminate DNS rebinding / TOCTOU SSRF
    context = ssl.create_default_context()
    raw_sock = socket.create_connection((pinned_ip, port), timeout=UPSTREAM_TIMEOUT)
    tls_sock = context.wrap_socket(raw_sock, server_hostname=host)

    connection = http.client.HTTPSConnection(host, port, timeout=UPSTREAM_TIMEOUT)
    connection.sock = tls_sock
    try:
        connection.request(method, path, body=body or None, headers=headers)
        response = connection.getresponse()
        data = response.read(CONFIG["max_response_bytes"] + 1)
        if len(data) > CONFIG["max_response_bytes"]:
            raise ValueError("upstream response exceeded max_response_bytes")

        # Inbound response DLP scan to protect against reflected or leaked credentials
        try:
            resp_text = data.decode("utf-8")
            resp_findings = scan_text(resp_text)
            if resp_findings:
                rules = sorted({f.rule for f in resp_findings})
                log("response_dlp_redact", host=host, method=method, rules=rules)
                data = redact_text(resp_text).encode("utf-8")
        except UnicodeDecodeError:
            pass

        response_headers: list[tuple[str, str]] = []
        for key, value in response.getheaders():
            if key.lower() in {"connection", "transfer-encoding", "content-length"}:
                continue
            response_headers.append((key, value))
        return response.status, response_headers, data
    finally:
        connection.close()


class MainHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = CONFIG["request_timeout_seconds"]

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
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
        raw_length = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_length)
        except ValueError:
            self._send_json(400, {"error": "invalid Content-Length"})
            return None
        if length < 0 or length > CONFIG["max_request_bytes"]:
            self._send_json(413, {"error": "request body too large"})
            return None
        return self.rfile.read(length)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.split("?", 1)[0] == "/health":
            self._send_json(200, {"status": "ok"})
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path.split("?", 1)[0] != "/request":
            self._send_json(404, {"error": "not found"})
            return
        transfer_encoding = self.headers.get("Transfer-Encoding", "").strip().lower()
        if transfer_encoding and transfer_encoding != "identity":
            self._send_json(415, {"error": "unsupported Transfer-Encoding"})
            return
        content_encoding = self.headers.get("Content-Encoding", "identity").strip().lower()
        if content_encoding in UNSUPPORTED_ENCODINGS or content_encoding not in {
            "",
            "identity",
        }:
            self._send_json(
                415,
                {"error": "compressed request bodies cannot be inspected and are rejected"},
            )
            return
        raw_body = self._read_body()
        if raw_body is None:
            return
        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(400, {"error": "request body must be JSON"})
            return

        method = str(payload.get("method", "GET")).upper()
        url = str(payload.get("url", ""))
        raw_headers = payload.get("headers", {})
        if not isinstance(raw_headers, dict):
            self._send_json(400, {"error": "headers must be an object"})
            return
        body_value = payload.get("body", "")
        if isinstance(body_value, (dict, list)):
            body = json.dumps(body_value).encode("utf-8")
        elif isinstance(body_value, str):
            body = body_value.encode("utf-8")
        elif body_value in (None, ""):
            body = b""
        else:
            self._send_json(400, {"error": "body must be a string or JSON object"})
            return

        if method not in CONFIG.get("allowed_methods", []):
            self._send_json(403, {"error": f"method {method} is not allowed"})
            return
        if len(body) > CONFIG["max_request_bytes"]:
            self._send_json(413, {"error": "request body too large"})
            return

        try:
            target = urllib.parse.urlsplit(url)
            if target.scheme != "https" or not target.hostname:
                raise ValueError("url must be an absolute https URL")
            port = target.port or 443
            if port not in CONFIG.get("allowed_ports", [443]):
                raise ValueError("target port is not allowed")
            if target.username or target.password:
                raise ValueError("URL userinfo is not allowed")
            if not _host_matches(target.hostname, CONFIG.get("approvable_domains", [])):
                raise ValueError("target host is not in approvable_domains")
            _resolve_public(target.hostname, port)
        except ValueError as exc:
            self._send_json(403, {"error": str(exc)})
            return

        headers = _sanitize_headers(raw_headers)
        findings = _scan_request(method, url, headers, body)
        if findings:
            rules = sorted({finding.rule for finding in findings})
            log("request_dlp_block", host=target.hostname, method=method, rules=rules)
            self._send_json(
                403,
                {"error": "Blocked by egress DLP: potential secret detected", "rules": rules},
            )
            return

        request_id = uuid.uuid4().hex
        auto_approve = _host_matches(
            target.hostname, CONFIG.get("auto_approve_domains", [])
        )
        if CONFIG.get("approval_required", True) and not auto_approve:
            preview_max = 2000
            preview = redact_text(body.decode("utf-8", "replace"))[:preview_max]
            import hashlib
            body_sha = hashlib.sha256(body).hexdigest()
            is_truncated = len(body) > preview_max

            pending = PendingRequest(
                request_id=request_id,
                method=method,
                url=url,
                headers=headers,
                body=body,
                preview=preview,
                dlp_rules=[],
                body_bytes=len(body),
                body_sha256=body_sha,
                truncated=is_truncated,
            )
            with PENDING_LOCK:
                if len(PENDING) >= CONFIG["max_pending_requests"]:
                    self._send_json(
                        429,
                        {"error": "too many pending egress requests; wait for approval or deny"},
                    )
                    log("pending_limit", limit=CONFIG["max_pending_requests"])
                    return
                PENDING[request_id] = pending
            log(
                "approval_required",
                id=request_id,
                host=target.hostname,
                method=method,
                body_bytes=len(body),
            )
            if not pending.event.wait(CONFIG["approval_timeout_seconds"]):
                with PENDING_LOCK:
                    PENDING.pop(request_id, None)
                self._send_json(408, {"error": "egress approval timed out", "id": request_id})
                return
            with PENDING_LOCK:
                PENDING.pop(request_id, None)
            if not pending.approved:
                log("request_denied", id=request_id, host=target.hostname)
                self._send_json(
                    403,
                    {"error": "egress request denied", "id": request_id, "reason": pending.denied_reason},
                )
                return

        _inject_credential(target.hostname, headers)
        try:
            status, response_headers, data = _forward(method, url, headers, body)
        except Exception as exc:  # noqa: BLE001
            log("upstream_error", id=request_id, host=target.hostname, error=type(exc).__name__)
            self._send_json(502, {"error": "upstream request failed", "id": request_id})
            return

        self.send_response(status)
        for key, value in response_headers:
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.send_header("X-Agent-Paladin-Request-ID", request_id)
        self.end_headers()
        if method != "HEAD":
            self.wfile.write(data)
        self.wfile.flush()
        log(
            "request_forwarded",
            id=request_id,
            host=target.hostname,
            method=method,
            status=status,
            response_bytes=len(data),
        )


class AdminHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = CONFIG["request_timeout_seconds"]

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        return

    def _send_json(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/health":
            self._send_json(200, {"status": "ok"})
            return
        if path == "/pending":
            with PENDING_LOCK:
                items = [
                    {
                        "id": item.request_id,
                        "method": item.method,
                        "url": item.url,
                        "body_preview": item.preview,
                        "created": item.created,
                        "body_bytes": item.body_bytes,
                        "body_sha256": item.body_sha256,
                        "truncated": item.truncated,
                    }
                    for item in PENDING.values()
                ]
            self._send_json(200, {"pending": items})
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        parts = [part for part in path.split("/") if part]
        if len(parts) != 2 or parts[0] not in {"approve", "deny"}:
            self._send_json(404, {"error": "not found"})
            return
        action, request_id = parts
        with PENDING_LOCK:
            pending = PENDING.get(request_id)
        if pending is None:
            self._send_json(404, {"error": "unknown or expired request"})
            return
        pending.approved = action == "approve"
        pending.denied = action == "deny"
        pending.denied_reason = "" if pending.approved else "denied by operator"
        pending.event.set()
        self._send_json(200, {"id": request_id, "action": action})
        log("approval_decision", id=request_id, action=action)


def main() -> None:
    log(
        "starting",
        listen=f"{LISTEN_HOST}:{LISTEN_PORT}",
        admin=f"{ADMIN_HOST}:{ADMIN_PORT}",
        approvable_domains=CONFIG.get("approvable_domains", []),
    )
    admin_server = ThreadingHTTPServer((ADMIN_HOST, ADMIN_PORT), AdminHandler)
    main_server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), MainHandler)
    threading.Thread(target=admin_server.serve_forever, daemon=True).start()
    try:
        main_server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        main_server.server_close()
        admin_server.shutdown()
        admin_server.server_close()


if __name__ == "__main__":
    main()
