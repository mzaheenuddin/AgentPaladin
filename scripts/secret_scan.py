#!/usr/bin/env python3
"""Pattern-based secret scanner for snapshots, changed files, and exports."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from common import git_safe_env
from dlp_patterns import scan_text

DEFAULT_EXCLUDES = {
    ".git",
    ".agent",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "target",
    ".next",
    ".nuxt",
    ".cache",
    "coverage",
    "vendor",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
}

SKIP_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".gz",
    ".tgz",
    ".bz2",
    ".xz",
    ".7z",
    ".jar",
    ".war",
    ".class",
    ".so",
    ".dylib",
    ".dll",
    ".exe",
    ".bin",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".mp3",
    ".mp4",
    ".mov",
    ".sqlite",
    ".sqlite3",
    ".db",
    ".p12",
    ".pfx",
    ".kdbx",
    ".jks",
    ".keystore",
}


def _git_files(root: Path) -> list[Path] | None:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        capture_output=True,
        check=False,
        env=git_safe_env(),
    )
    if result.returncode != 0:
        return None
    files: list[Path] = []
    for item in result.stdout.split(b"\0"):
        if item:
            files.append(root / item.decode("utf-8", "surrogateescape"))
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--others", "--exclude-standard", "-z"],
        capture_output=True,
        check=False,
        env=git_safe_env(),
    )
    if result.returncode == 0:
        for item in result.stdout.split(b"\0"):
            if item:
                files.append(root / item.decode("utf-8", "surrogateescape"))
    return files


def _walk_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for current, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            name for name in dirnames if name.casefold() not in DEFAULT_EXCLUDES
        ]
        for name in filenames:
            files.append(Path(current) / name)
    return files


def _excluded(path: Path, root: Path) -> bool:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return True
    if any(part.casefold() in DEFAULT_EXCLUDES for part in relative.parts):
        return True
    if path.suffix.lower() in SKIP_SUFFIXES:
        return True
    if path.name.endswith(".min.js") or path.name.endswith(".map"):
        return True
    return False


def scan_file(
    path: Path,
    *,
    root: Path,
    include_entropy: bool = False,
    max_bytes: int = 2 * 1024 * 1024,
) -> list[dict[str, object]]:
    if _excluded(path, root):
        return []
    # Scan only paths that resolve inside the scanned tree, including files
    # reached through a symlinked parent directory. A workspace symlink can
    # otherwise make the host scanner read an arbitrary host file when the
    # agent-created snapshot is inspected.
    try:
        path.resolve().relative_to(root.resolve())
    except (OSError, RuntimeError, ValueError):
        return []
    try:
        stat = path.stat()
    except OSError:
        return []
    if not path.is_file() or stat.st_size == 0 or stat.st_size > max_bytes:
        return []
    try:
        data = path.read_bytes()
    except OSError:
        return []
    if b"\x00" in data[:4096]:
        return []
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = data.decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            return []

    findings = scan_text(text, include_entropy=include_entropy)
    if not findings:
        return []
    relative = str(path.relative_to(root))
    output: list[dict[str, object]] = []
    for finding in findings:
        line = text.count("\n", 0, finding.start) + 1
        output.append(
            {
                "path": relative,
                "line": line,
                "rule": finding.rule,
                "preview": finding.preview,
            }
        )
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--git-only", action="store_true")
    parser.add_argument("--include-entropy", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--max-bytes", type=int, default=2 * 1024 * 1024)
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    if not root.exists():
        print(f"error: path does not exist: {root}", file=sys.stderr)
        return 2

    if root.is_file():
        files = [root]
        root = root.parent
    elif args.git_only:
        files = _git_files(root) or _walk_files(root)
    else:
        files = _walk_files(root)

    findings: list[dict[str, object]] = []
    for path in files:
        findings.extend(
            scan_file(
                path,
                root=root,
                include_entropy=args.include_entropy,
                max_bytes=args.max_bytes,
            )
        )

    if args.json:
        print(json.dumps({"findings": findings}, indent=2))
    else:
        for item in findings:
            print(
                f"{item['path']}:{item['line']}: {item['rule']}: {item['preview']}"
            )
        if not findings:
            print("No secret patterns found.")

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
