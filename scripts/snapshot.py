#!/usr/bin/env python3
"""Create a sanitized, disposable Git snapshot of a project."""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from common import git_safe_env
from secret_scan import scan_file

EXCLUDED_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".agent",
    ".opencode",
    ".ssh",
    ".aws",
    ".gnupg",
    ".kube",
    ".docker",
    "secrets",
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
    ".idea",
    ".DS_Store",
}

EXCLUDED_PATTERNS = [
    ".env",
    ".env.*",
    ".envrc",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".git-credentials",
    ".gitconfig",
    ".bash_history",
    ".zsh_history",
    ".python_history",
    ".lesshst",
    "opencode.json",
    "opencode.jsonc",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.kdbx",
    "*.jks",
    "*.keystore",
    "credentials.json",
    "service-account*.json",
    "terraform.tfstate*",
    "*.log",
    "*.sqlite",
    "*.sqlite3",
]

ALLOWED_ENV_TEMPLATES = {".env.example", ".env.sample", ".env.template"}
EXCLUDED_NAMES_LOWER = {name.casefold() for name in EXCLUDED_NAMES}


def _load_git_files(source: Path) -> list[Path] | None:
    result = subprocess.run(
        ["git", "-C", str(source), "ls-files", "-z"],
        capture_output=True,
        check=False,
        env=git_safe_env(),
    )
    if result.returncode != 0:
        return None
    files: list[Path] = []
    for item in result.stdout.split(b"\0"):
        if item:
            files.append(source / item.decode("utf-8", "surrogateescape"))
    result = subprocess.run(
        ["git", "-C", str(source), "ls-files", "--others", "--exclude-standard", "-z"],
        capture_output=True,
        check=False,
        env=git_safe_env(),
    )
    if result.returncode == 0:
        for item in result.stdout.split(b"\0"):
            if item:
                files.append(source / item.decode("utf-8", "surrogateescape"))
    return files


def _walk_files(source: Path) -> list[Path]:
    files: list[Path] = []
    for current, dirnames, filenames in os.walk(source):
        dirnames[:] = [
            name for name in dirnames if name.casefold() not in EXCLUDED_NAMES_LOWER
        ]
        for name in filenames:
            files.append(Path(current) / name)
    return files


def is_excluded(relative: Path) -> bool:
    parts = [part.casefold() for part in relative.parts]
    if any(part in EXCLUDED_NAMES_LOWER for part in parts):
        return True
    name = relative.name.casefold()
    if name in ALLOWED_ENV_TEMPLATES:
        return False
    if name == ".env" or name.startswith(".env."):
        return True
    relative_text = str(relative).casefold()
    for pattern in EXCLUDED_PATTERNS:
        if fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(relative_text, pattern):
            return True
    return False


def safe_symlink(path: Path, source: Path) -> bool:
    try:
        target = path.resolve(strict=False)
    except (OSError, RuntimeError):
        # Path.resolve raises RuntimeError on a symlink loop on some Python
        # versions; treat it as unsafe instead of aborting the snapshot.
        return False
    try:
        target.relative_to(source)
    except ValueError:
        return False
    return True


def copy_file(source: Path, destination: Path, source_root: Path) -> None:
    if source.is_symlink():
        if not safe_symlink(source, source_root):
            raise ValueError(f"symlink escapes the project: {source}")
        link_target = os.readlink(source)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.symlink_to(link_target)
        return
    if not source.is_file():
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination, follow_symlinks=False)


def git_environment(hooks: Path) -> dict[str, str]:
    env = git_safe_env()
    env.update(
        {
            "GIT_CONFIG_COUNT": "5",
            "GIT_CONFIG_KEY_4": "core.hooksPath",
            "GIT_CONFIG_VALUE_4": str(hooks),
        }
    )
    return env


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--dest", required=True)
    parser.add_argument("--manifest", default=None)
    parser.add_argument("--include-env", action="store_true")
    parser.add_argument("--allow-secrets", action="store_true")
    args = parser.parse_args(argv)

    source = Path(args.source).resolve()
    destination = Path(args.dest).resolve()
    if not source.is_dir():
        print(f"error: source is not a directory: {source}", file=sys.stderr)
        return 2
    if destination.is_symlink():
        print(f"error: snapshot destination is a symlink: {destination}", file=sys.stderr)
        return 2
    if destination.exists():
        if not destination.is_dir() or any(destination.iterdir()):
            print(
                f"error: snapshot destination is not an empty directory: {destination}",
                file=sys.stderr,
            )
            return 2
    destination.mkdir(parents=True, exist_ok=True)

    files = _load_git_files(source) or _walk_files(source)
    copied = 0
    skipped: list[str] = []
    symlink_warnings: list[str] = []

    for path in files:
        try:
            relative = path.relative_to(source)
        except ValueError:
            continue
        excluded = is_excluded(relative)
        if (
            excluded
            and args.include_env
            and path.name.startswith(".env")
            and path.name not in ALLOWED_ENV_TEMPLATES
        ):
            excluded = False
        if excluded:
            skipped.append(str(relative))
            continue
        if path.name in ALLOWED_ENV_TEMPLATES:
            pass
        elif args.include_env and path.name.startswith(".env"):
            pass
        try:
            copy_file(path, destination / relative, source)
            copied += 1
        except ValueError as exc:
            symlink_warnings.append(str(exc))
        except OSError as exc:
            print(f"warning: could not copy {relative}: {exc}", file=sys.stderr)

    empty_hooks = destination.parent / ".agent-paladin-empty-hooks"
    empty_hooks.mkdir(parents=True, exist_ok=True)
    env = git_environment(empty_hooks)
    try:
        init = subprocess.run(
            ["git", "-C", str(destination), "init", "-q"], env=env, check=False
        )
        if init.returncode != 0:
            print("error: git init failed", file=sys.stderr)
            return 2
        add = subprocess.run(
            ["git", "-C", str(destination), "add", "-A"], env=env, check=False
        )
        if add.returncode != 0:
            print("error: git add failed", file=sys.stderr)
            return 2
        commit = subprocess.run(
            [
                "git",
                "-C",
                str(destination),
                "-c",
                "user.name=Agent Paladin",
                "-c",
                "user.email=paladin@localhost",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "baseline",
            ],
            env=env,
            check=False,
        )
        if commit.returncode != 0:
            print("error: git baseline commit failed", file=sys.stderr)
            return 2

        baseline = subprocess.run(
            ["git", "-C", str(destination), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        ).stdout.strip()
    finally:
        shutil.rmtree(empty_hooks, ignore_errors=True)

    if not baseline:
        print("error: could not determine the snapshot baseline commit", file=sys.stderr)
        return 2

    findings: list[dict[str, object]] = []
    for current, dirnames, filenames in os.walk(destination, followlinks=False):
        dirnames[:] = [name for name in dirnames if name != ".git"]
        for name in filenames:
            findings.extend(scan_file(Path(current) / name, root=destination))

    manifest = {
        "source": str(source),
        "destination": str(destination),
        "baseline": baseline,
        "copied_files": copied,
        "skipped_files": skipped,
        "symlink_warnings": symlink_warnings,
        "secret_findings": findings,
    }
    if args.manifest:
        Path(args.manifest).write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )

    print(f"snapshot: {destination}")
    print(f"copied files: {copied}")
    print(f"baseline commit: {baseline}")
    if symlink_warnings:
        print("symlink warnings:", file=sys.stderr)
        for warning in symlink_warnings:
            print(f"  {warning}", file=sys.stderr)
    if findings:
        print("secret scanner findings:", file=sys.stderr)
        for finding in findings:
            print(
                f"  {finding['path']}:{finding['line']}: {finding['rule']}: {finding['preview']}",
                file=sys.stderr,
            )
        if not args.allow_secrets:
            print("Snapshot aborted: remove or replace the secrets and retry (or pass --allow-secrets).", file=sys.stderr)
            return 1
        print("WARNING: continuing snapshot despite secret findings (--allow-secrets)", file=sys.stderr)

    print("secret scan: clean" if not findings else "secret scan: allowed with warnings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
