"""Shared secret-pattern detection for the host scanner, prompt DLP, and broker.

This is intentionally pattern-based. It is useful for accidental leaks and for
catching well-known credential formats. It is not a semantic data-loss
prevention system and must not be described as one.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Iterable

PLACEHOLDER_MARKERS = (
    "example",
    "sample",
    "dummy",
    "fake",
    "placeholder",
    "changeme",
    "change-me",
    "redacted",
    "your_",
    "your-",
    "<",
    ">",
    "${",
    "xxxx",
    "****",
    "not-a-real",
)

# (rule name, compiled regex)
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "private-key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
        ),
    ),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    (
        "aws-secret-key",
        re.compile(
            r"(?i)\baws_?secret_?access_?key\b\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})"
        ),
    ),
    (
        "github-token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    ),
    ("provider-key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("stripe-live-key", re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    (
        "jwt",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
        ),
    ),
    (
        "database-url-with-password",
        re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s/@]+:[^@\s/]+@"
        ),
    ),
    (
        "generic-credential-assignment",
        re.compile(
            r"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd|access[_-]?key|client[_-]?secret)\b"
            r"\s*[:=]\s*['\"]?([A-Za-z0-9_\-./+=]{12,})['\"]?"
        ),
    ),
    ("canary-token", re.compile(r"\bCANARY_[A-Za-z0-9_]{8,}\b")),
]

_ENTROPY_CANDIDATE = re.compile(r"[A-Za-z0-9+/=_-]{32,160}")


@dataclass(frozen=True)
class Finding:
    rule: str
    start: int
    end: int
    preview: str

    def as_dict(self) -> dict[str, object]:
        return {
            "rule": self.rule,
            "start": self.start,
            "end": self.end,
            "preview": self.preview,
        }


def _is_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in PLACEHOLDER_MARKERS)


def _is_generic_credential_false_positive(match: re.Match) -> bool:
    try:
        key_name = match.group(1).lower()
        val = match.group(2)
    except IndexError:
        return False

    if re.match(r"^(?:application|text|image|audio|video)/[a-zA-Z0-9._+-]+$", val, re.IGNORECASE):
        return True

    auth_prefixes = (
        "api",
        "auth",
        "access",
        "bearer",
        "refresh",
        "session",
        "secret",
        "jwt",
        "oauth",
        "bot",
        "client",
    )
    is_auth_token_key = any(p in key_name for p in auth_prefixes)

    if not is_auth_token_key:
        if not any(c.isdigit() for c in val) and re.match(
            r"^[a-zA-Z_][a-zA-Z0-9_-]*(?:\.[a-zA-Z_][a-zA-Z0-9_-]*)+$", val
        ):
            return True
        if not any(c.isdigit() for c in val) and shannon_entropy(val) < 3.8:
            return True

    return False


def _preview(value: str) -> str:
    # Never return enough of a credential to be useful.
    if len(value) <= 6:
        return value[:2] + "..."
    return value[:4] + "..." + value[-2:]


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def scan_text(
    text: str,
    *,
    include_entropy: bool = False,
    entropy_threshold: float = 4.2,
) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, int, int]] = set()

    for rule, pattern in _PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            if _is_placeholder(value):
                continue
            if rule == "generic-credential-assignment" and _is_generic_credential_false_positive(match):
                continue
            key = (rule, match.start(), match.end())
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    rule=rule,
                    start=match.start(),
                    end=match.end(),
                    preview=_preview(value),
                )
            )

    if include_entropy:
        for match in _ENTROPY_CANDIDATE.finditer(text):
            value = match.group(0)
            if _is_placeholder(value):
                continue
            if shannon_entropy(value) < entropy_threshold:
                continue
            key = ("high-entropy", match.start(), match.end())
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    rule="high-entropy",
                    start=match.start(),
                    end=match.end(),
                    preview=_preview(value),
                )
            )

    findings.sort(key=lambda item: (item.start, item.end, item.rule))
    return findings


def redact_text(text: str) -> str:
    findings = scan_text(text)
    if not findings:
        return text
    output: list[str] = []
    cursor = 0
    for finding in findings:
        if finding.start < cursor:
            continue
        output.append(text[cursor : finding.start])
        output.append(f"[REDACTED:{finding.rule}]")
        cursor = finding.end
    output.append(text[cursor:])
    return "".join(output)


def summary(findings: Iterable[Finding]) -> list[dict[str, object]]:
    return [finding.as_dict() for finding in findings]
