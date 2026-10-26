#!/usr/bin/env python3
"""Export a reviewed patch from a snapshot run, with a safety gate."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

from common import config, fail, git_safe_env
from dlp_patterns import scan_text
from path_policy import classify
from secret_scan import scan_file

SAFE_GIT_CONFIG = """[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
"""


def _latest_run(state_dir: Path) -> Path | None:
    runs = []
    for path in (state_dir / "runs").glob("*"):
        if path.is_dir() and (path / "manifest.json").is_file():
            runs.append(path)
    runs.sort(key=lambda path: path.stat().st_mtime, reverse=True)
    return runs[0] if runs else None


def _run_dir(arg: str | None, cfg: dict[str, str]) -> Path:
    if arg:
        candidate = Path(arg)
        if candidate.is_dir():
            return candidate.resolve()
        candidate = Path(cfg["STATE_DIR"]) / "runs" / arg
        if candidate.is_dir():
            return candidate
        fail(f"run directory not found: {arg}")
    latest = _latest_run(Path(cfg["STATE_DIR"]))
    if latest is None:
        fail("no snapshot runs found")
    return latest


def _git(
    args: list[str], cwd: Path, *, check: bool = True, text: bool = True
) -> subprocess.CompletedProcess:
    result = subprocess.run(
        ["git", "-C", str(cwd), *args],
        capture_output=True,
        text=text,
        check=False,
        env=git_safe_env(),
    )
    if check and result.returncode != 0:
        error = result.stderr if text else result.stderr.decode("utf-8", "replace")
        fail(error.strip() or f"git {' '.join(args)} failed")
    return result


def _remove(path: Path) -> None:
    """Remove a workspace-controlled path without following symlinks."""
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        path.unlink()
    else:
        shutil.rmtree(path)


def _sanitize_workspace_git(workspace: Path) -> None:
    """Reset snapshot Git metadata before any host-side Git command.

    The agent controls the snapshot workspace, including ``.git``. A malicious
    repository can otherwise define ``filter.*.clean``, ``core.fsmonitor``, or
    an external diff program and execute it on the host during export. The
    snapshot is disposable, so replace its metadata with a minimal safe config
    and remove hook/attribute/alternate locations that could point outside.
    """
    git_dir = workspace / ".git"
    try:
        mode = git_dir.lstat().st_mode
    except FileNotFoundError:
        fail("snapshot workspace has no .git directory")
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        fail("snapshot .git is not a regular directory; refusing to export")

    try:
        resolved = git_dir.resolve()
        resolved.relative_to(workspace.resolve())
    except (OSError, RuntimeError, ValueError):
        fail("snapshot .git does not resolve to a real directory inside the workspace")

    try:
        for current, dirnames, filenames in os.walk(git_dir, followlinks=False):
            for name in [*dirnames, *filenames]:
                path = Path(current) / name
                if path.is_symlink():
                    fail(f"snapshot .git contains a symlink: {path.relative_to(workspace)}")

        for name in ("hooks", "info", "modules", "worktrees"):
            _remove(git_dir / name)
        for name in ("config", "config.worktree", "index", "index.lock", "commondir", "gitdir"):
            _remove(git_dir / name)
        for name in ("alternates", "http-alternates"):
            _remove(git_dir / "objects" / "info" / name)

        (git_dir / "config").write_text(SAFE_GIT_CONFIG, encoding="utf-8")
    except OSError as exc:
        fail(f"could not sanitize snapshot .git metadata: {exc}")


def _changed_files(workspace: Path, baseline: str) -> list[str]:
    result = _git(
        ["diff", "--cached", "--name-only", "-z", "--no-renames", baseline],
        workspace,
        check=False,
    )
    if result.returncode != 0:
        fail(
            result.stderr.strip()
            or "could not inspect the snapshot diff; refusing to export"
        )
    return [item for item in result.stdout.split("\0") if item]


def _check_symlinks(workspace: Path, files: list[str]) -> list[str]:
    problems: list[str] = []
    for relative in files:
        path = workspace / relative
        cursor = workspace
        traversed_symlink = None
        for part in Path(relative).parts[:-1]:
            cursor = cursor / part
            if cursor.is_symlink():
                traversed_symlink = cursor
                break
        if traversed_symlink is not None:
            problems.append(
                f"path traverses symlinked directory: {relative} -> "
                f"{os.readlink(traversed_symlink)}"
            )
            continue
        if not path.is_symlink():
            continue
        link = os.readlink(path)
        if os.path.isabs(link):
            problems.append(f"absolute symlink: {relative} -> {link}")
            continue
        try:
            resolved = (path.parent / link).resolve()
            resolved.relative_to(workspace)
        except (OSError, RuntimeError, ValueError):
            problems.append(f"symlink escapes repository: {relative} -> {link}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", default=None)
    parser.add_argument("--project", default=None)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--allow-risky", action="store_true")
    args = parser.parse_args(argv)

    cfg = config()
    run_dir = _run_dir(args.run, cfg)
    manifest_path = run_dir / "manifest.json"
    if not manifest_path.exists():
        fail(f"manifest not found: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("workspace_mode") != "snapshot":
        fail("export is only available for snapshot runs; use bin/audit for direct modes")

    workspace = run_dir / "workspace"
    baseline = manifest.get("baseline")
    if not workspace.is_dir() or not baseline:
        fail("snapshot workspace or baseline is missing")

    project_value = args.project or manifest.get("project_dir") or cfg.get("PROJECT_DIR")
    if not project_value:
        fail("project directory is not known; pass --project")
    project = Path(project_value).expanduser().resolve()

    _sanitize_workspace_git(workspace)
    _git(["add", "-A"], workspace)
    patch_result = _git(
        ["diff", "--cached", "--binary", "--no-ext-diff", "--no-textconv", baseline],
        workspace,
        check=False,
        text=False,
    )
    if patch_result.returncode != 0:
        fail(patch_result.stderr.decode("utf-8", "replace").strip())
    patch_bytes = patch_result.stdout
    patch_text = patch_bytes.decode("utf-8", "replace")
    stat_result = _git(
        ["diff", "--cached", "--stat", "--no-ext-diff", "--no-textconv", baseline],
        workspace,
        check=False,
    )
    changed = _changed_files(workspace, baseline)

    blocked: list[str] = []
    risky: list[str] = []
    secret_findings: list[dict[str, object]] = []
    for relative in changed:
        blocked_path, risky_path = classify(relative)
        if blocked_path:
            blocked.append(relative)
        if risky_path:
            risky.append(relative)
        path = workspace / relative
        if path.is_file() and not path.is_symlink():
            secret_findings.extend(scan_file(path, root=workspace))
        elif path.is_symlink():
            link = os.readlink(path)
            if not os.path.isabs(link):
                target = path.parent / link
                if target.is_file():
                    secret_findings.extend(scan_file(target, root=workspace))

    added_lines = "\n".join(
        line[1:]
        for line in patch_text.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    )
    patch_findings = scan_text(added_lines)
    symlink_problems = _check_symlinks(workspace, changed)

    export_dir = run_dir / "export"
    export_dir.mkdir(parents=True, exist_ok=True)
    (export_dir / "changes.patch").write_bytes(patch_bytes)
    (export_dir / "changes.stat").write_text(stat_result.stdout, encoding="utf-8")
    report = {
        "run": run_dir.name,
        "project": str(project),
        "baseline": baseline,
        "changed_files": changed,
        "blocked_paths": blocked,
        "risky_paths": risky,
        "symlink_problems": symlink_problems,
        "secret_findings": secret_findings,
        "patch_secret_rules": sorted({finding.rule for finding in patch_findings}),
        "patch_bytes": len(patch_bytes),
    }
    (export_dir / "report.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )

    print(f"run: {run_dir.name}")
    print(f"changed files: {len(changed)}")
    for relative in changed:
        print(f"  {relative}")
    if blocked:
        print("BLOCKED paths:", file=sys.stderr)
        for relative in blocked:
            print(f"  {relative}", file=sys.stderr)
    if symlink_problems:
        print("BLOCKED symlinks:", file=sys.stderr)
        for problem in symlink_problems:
            print(f"  {problem}", file=sys.stderr)
    if secret_findings:
        print("BLOCKED secret findings:", file=sys.stderr)
        for finding in secret_findings:
            print(
                f"  {finding['path']}:{finding['line']}: {finding['rule']}",
                file=sys.stderr,
            )
    if patch_findings:
        print(
            "BLOCKED secret-like text in patch: "
            + ", ".join(sorted({finding.rule for finding in patch_findings})),
            file=sys.stderr,
        )
    if risky:
        print("Risky paths (review before applying):", file=sys.stderr)
        for relative in risky:
            print(f"  {relative}", file=sys.stderr)

    print(f"patch: {export_dir / 'changes.patch'}")
    print(f"report: {export_dir / 'report.json'}")

    blocked_result = bool(blocked or symlink_problems or secret_findings or patch_findings)
    risky_result = bool(risky)

    if blocked_result:
        print("Export is blocked; no changes were applied.", file=sys.stderr)
        return 1
    if risky_result and not args.allow_risky:
        print("Export requires --allow-risky for the flagged files.", file=sys.stderr)
        return 1
    if not args.apply:
        print("Review the patch, then apply with: bin/export --apply [--allow-risky]")
        return 0

    git_path = project / ".git"
    if not project.is_dir() or not git_path.exists():
        fail(f"project is not a Git repository: {project}")
    if git_path.is_symlink():
        fail("project .git is a symlink; refusing to apply through it")
    if git_path.is_dir():
        for current, dirnames, filenames in os.walk(git_path, followlinks=False):
            for name in [*dirnames, *filenames]:
                metadata = Path(current) / name
                if metadata.is_symlink():
                    fail(
                        "project .git contains a symlink; refusing to apply through it: "
                        f"{metadata.relative_to(project)} -> {os.readlink(metadata)}"
                    )
    project_symlink_problems = _check_symlinks(project, changed)
    if project_symlink_problems:
        fail(
            "project path traverses an unsafe symlink: "
            + "; ".join(project_symlink_problems[:3])
        )
    status = _git(["status", "--porcelain"], project, check=False)
    if status.returncode != 0:
        fail(status.stderr.strip() or "could not inspect project status")
    if status.stdout.strip() and not args.force:
        fail("project has uncommitted changes; pass --force to apply anyway")
    patch_path = str(export_dir / "changes.patch")
    check = _git(["apply", "--check", "--3way", patch_path], project, check=False)
    if check.returncode != 0:
        fail(f"patch does not apply cleanly: {check.stderr.strip()}")
    apply_result = _git(["apply", "--index", "--3way", patch_path], project, check=False)
    if apply_result.returncode != 0:
        fail(f"patch apply failed: {apply_result.stderr.strip()}")
    print(f"applied patch to {project}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
