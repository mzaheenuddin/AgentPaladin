#!/usr/bin/env python3
"""Audit changes made in a direct-mount workspace."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from common import ROOT, config, git_safe_env
from path_policy import classify
from secret_scan import DEFAULT_EXCLUDES, scan_file


def _git_paths(project: Path, args: list[str]) -> list[str] | None:
    result = subprocess.run(
        ["git", "-C", str(project), *args],
        capture_output=True,
        text=True,
        check=False,
        env=git_safe_env(),
    )
    if result.returncode != 0:
        return None
    return [item for item in result.stdout.split("\0") if item]


def _excluded_path(relative: str) -> bool:
    parts = Path(relative).parts
    return any(part.casefold() in DEFAULT_EXCLUDES for part in parts)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", default=None)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    project_value = args.project or config().get("PROJECT_DIR")
    if not project_value:
        cwd = Path.cwd().resolve()
        if cwd != ROOT:
            project_value = str(cwd)
        else:
            print("error: PROJECT_DIR is not set; run inside your project or pass --project", file=sys.stderr)
            return 2
    project = Path(project_value).expanduser().resolve()
    if not project.is_dir():
        print(f"error: project directory does not exist: {project}", file=sys.stderr)
        return 2
    git_path = project / ".git"
    if not git_path.exists():
        print(f"note: {project} is not a Git repository; audit skipped")
        return 0
    if git_path.is_symlink():
        print(
            "error: project .git is a symlink; refusing to audit an external repository",
            file=sys.stderr,
        )
        return 2

    symlink_problems: list[str] = []
    # Direct-commit makes parts of .git writable. A symlink there can point
    # outside the repository on the host and be followed by later host-side Git
    # commands, so reject the audit before invoking Git on the repository.
    if git_path.is_dir():
        for current, dirnames, filenames in os.walk(git_path, followlinks=False):
            for name in [*dirnames, *filenames]:
                path = Path(current) / name
                if path.is_symlink():
                    symlink_problems.append(
                        f"symlink inside .git: {path.relative_to(project)} -> "
                        f"{os.readlink(path)}"
                    )
    if symlink_problems:
        print("error: .git contains unsafe symlinks:", file=sys.stderr)
        for problem in symlink_problems:
            print(f"  {problem}", file=sys.stderr)
        return 2

    changed: set[str] = set()
    commands = [
        ["diff", "--name-only", "-z", "--no-renames", "--no-ext-diff", "--no-textconv"],
        ["diff", "--cached", "--name-only", "-z", "--no-renames", "--no-ext-diff", "--no-textconv"],
        ["ls-files", "--others", "--exclude-standard", "-z"],
        # Ignored files still exist in the host working tree. Include the ones
        # that are not bulk directories so a newly-created ignored .env or
        # secrets file cannot slip past the post-run audit.
        ["ls-files", "--others", "--ignored", "--exclude-standard", "-z"],
    ]
    for command in commands:
        paths = _git_paths(project, command)
        if paths is None:
            print(
                f"error: git {' '.join(command)} failed; refusing to report a clean audit",
                file=sys.stderr,
            )
            return 2
        for relative in paths:
            if not _excluded_path(relative):
                changed.add(relative)
    changed.discard("")

    blocked: list[str] = []
    risky: list[str] = []
    secret_findings: list[dict[str, object]] = []

    for relative in sorted(changed):
        blocked_path, risky_path = classify(relative)
        if blocked_path:
            blocked.append(relative)
        if risky_path:
            risky.append(relative)
        path = project / relative
        cursor = project
        traversed_symlink = None
        for part in Path(relative).parts[:-1]:
            cursor = cursor / part
            if cursor.is_symlink():
                traversed_symlink = cursor
                break
        if traversed_symlink is not None:
            symlink_problems.append(
                f"path traverses symlinked directory: {relative} -> "
                f"{os.readlink(traversed_symlink)}"
            )
            continue
        if path.is_symlink():
            link = os.readlink(path)
            if os.path.isabs(link):
                symlink_problems.append(f"absolute symlink: {relative} -> {link}")
            else:
                target = path.parent / link
                try:
                    resolved = target.resolve()
                    resolved.relative_to(project)
                except (OSError, RuntimeError, ValueError):
                    symlink_problems.append(
                        f"symlink escapes repository: {relative} -> {link}"
                    )
                else:
                    if target.is_file():
                        secret_findings.extend(scan_file(target, root=project))
        elif path.is_file():
            secret_findings.extend(scan_file(path, root=project))

    report = {
        "project": str(project),
        "changed_files": sorted(changed),
        "blocked_paths": blocked,
        "risky_paths": risky,
        "symlink_problems": symlink_problems,
        "secret_findings": secret_findings,
    }

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        if not changed:
            print("No changes detected.")
        else:
            print(f"changed files: {len(changed)}")
            for relative in sorted(changed):
                print(f"  {relative}")
        if blocked:
            print("WARNING: high-risk paths changed:", file=sys.stderr)
            for relative in blocked:
                print(f"  {relative}", file=sys.stderr)
        if symlink_problems:
            print("WARNING: unsafe symlinks:", file=sys.stderr)
            for problem in symlink_problems:
                print(f"  {problem}", file=sys.stderr)
        if secret_findings:
            print("WARNING: secret patterns found in changed files:", file=sys.stderr)
            for finding in secret_findings:
                print(
                    f"  {finding['path']}:{finding['line']}: {finding['rule']}",
                    file=sys.stderr,
                )
        if risky:
            print("Review before executing anything in this repository:", file=sys.stderr)
            for relative in risky:
                print(f"  {relative}", file=sys.stderr)
        if blocked or symlink_problems or secret_findings:
            print(
                "Direct-mount mode cannot undo these changes. Review them before running tools on the host.",
                file=sys.stderr,
            )

    return 1 if (blocked or symlink_problems or secret_findings) else 0


if __name__ == "__main__":
    sys.exit(main())
