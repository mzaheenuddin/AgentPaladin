#!/usr/bin/env python3
"""Host and Docker preflight checks for Agent Paladin."""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path

from common import ROOT, config, fail, run

WARNINGS: list[str] = []
ERRORS: list[str] = []
PREFLIGHT_IMAGE = "alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f"


def ok(message: str) -> None:
    print(f"PASS  {message}")


def warn(message: str) -> None:
    WARNINGS.append(message)
    print(f"WARN  {message}")


def error(message: str) -> None:
    ERRORS.append(message)
    print(f"FAIL  {message}")


def check_command(name: str) -> None:
    if shutil.which(name):
        ok(f"{name} is available")
    else:
        error(f"{name} is not on PATH")


def check_docker() -> None:
    if not shutil.which("docker"):
        error("docker is not on PATH")
        return
    version = run(["docker", "version", "--format", "{{.Server.Version}}"], capture=True, check=False)
    if version.returncode != 0:
        error("Docker daemon is not reachable")
        return
    ok(f"Docker server {version.stdout.strip()}")
    compose = run(["docker", "compose", "version", "--short"], capture=True, check=False)
    if compose.returncode != 0:
        error("docker compose is not available")
    else:
        ok(f"Docker Compose {compose.stdout.strip()}")
    context = run(["docker", "context", "show"], capture=True, check=False)
    if context.returncode == 0:
        print(f"INFO  Docker context: {context.stdout.strip()}")
    info = run(
        ["docker", "info", "--format", "{{json .SecurityOptions}}"], capture=True, check=False
    )
    if info.returncode == 0:
        print(f"INFO  Docker security options: {info.stdout.strip()}")
    runtimes = run(
        ["docker", "info", "--format", "{{json .Runtimes}}"], capture=True, check=False
    )
    if runtimes.returncode == 0:
        try:
            names = ", ".join(json.loads(runtimes.stdout).keys())
            print(f"INFO  Docker runtimes: {names}")
        except json.JSONDecodeError:
            pass


def check_platform() -> None:
    system = platform.system()
    machine = platform.machine()
    print(f"INFO  platform: {system} {machine}")
    if system == "Darwin":
        warn(
            "Docker Desktop's Linux VM is shared with other containers; use a dedicated VM/Colima for stronger isolation."
        )
    if system == "Linux":
        uid = os.getuid()
        if uid == 0:
            error("run the wrapper as a normal user, not root")
        info = run(
            ["docker", "info", "--format", "{{json .SecurityOptions}}"],
            capture=True,
            check=False,
        ).stdout.lower()
        if "rootless" in info or "name=userns" in info:
            ok("Docker rootless or userns-remap is active")
        else:
            warn(
                "Docker is not rootless and userns-remap is not detected; a runtime escape has the host user's authority."
            )


def check_identity() -> None:
    uid = os.getuid()
    gid = os.getgid()
    if uid == 0:
        error("do not run Agent Paladin as root")
    else:
        ok(f"host identity {uid}:{gid}")
    print(f"INFO  Docker build/run UID:GID will be {uid}:{gid}")


def check_paths(cfg: dict[str, str]) -> None:
    state_dir = Path(cfg["STATE_DIR"])
    try:
        state_dir.mkdir(parents=True, exist_ok=True)
        state_dir.chmod(0o700)
        test = state_dir / ".preflight-write-test"
        test.write_text("ok", encoding="utf-8")
        test.unlink()
        ok(f"state directory is writable: {state_dir}")
    except OSError as exc:
        error(f"state directory is not writable: {state_dir} ({exc})")

    project = cfg.get("PROJECT_DIR")
    if not project:
        cwd = Path.cwd().resolve()
        if cwd != ROOT:
            project = str(cwd)
    if not project:
        warn("PROJECT_DIR is not set; running paladin from any project directory will automatically target that directory")
        return
    project_path = Path(project)
    if not project_path.is_dir():
        error(f"PROJECT_DIR does not exist: {project_path}")
    else:
        ok(f"project directory exists: {project_path}")


def check_bind_mount(cfg: dict[str, str]) -> None:
    state_dir = Path(cfg["STATE_DIR"])
    uid = os.getuid()
    gid = os.getgid()
    command = [
        "docker",
        "run",
        "--rm",
        "--user",
        f"{uid}:{gid}",
        "-v",
        f"{state_dir}:/state",
        PREFLIGHT_IMAGE,
        "sh",
        "-c",
        "touch /state/.preflight-bind-test",
    ]
    result = run(command, capture=True, check=False)
    if result.returncode != 0:
        error(
            "Docker bind mount write test failed; check Docker Desktop file sharing for the state directory."
        )
        return
    try:
        (state_dir / ".preflight-bind-test").unlink()
    except OSError:
        pass
    ok("Docker bind mount works with the host UID/GID")


def check_secrets() -> None:
    secrets = ROOT / "secrets"
    gateway = secrets / "GATEWAY_TOKEN"
    master = secrets / "LITELLM_MASTER_KEY"
    broker = secrets / "broker" / "GITHUB_TOKEN"

    for path in (secrets, secrets / "broker"):
        if path.is_symlink():
            error(f"secret directory is a symlink: {path}")
            continue
        if path.exists():
            mode = path.stat().st_mode & 0o777
            if mode & 0o077:
                warn(f"secret directory is group/world-accessible: {path} ({oct(mode)})")

    for path, label, pattern in (
        (gateway, "GATEWAY_TOKEN", r"[A-Za-z0-9_-]{16,128}"),
        (master, "LITELLM_MASTER_KEY", r"sk-[A-Za-z0-9_-]{16,}"),
    ):
        if path.is_symlink():
            error(f"secrets/{label} is a symlink; refusing to trust it")
        elif not path.exists() or path.stat().st_size == 0:
            error(f"secrets/{label} is missing; run bin/secrets init")
        else:
            try:
                value = path.read_text(encoding="utf-8").strip()
            except OSError as exc:
                error(f"secrets/{label} cannot be read: {exc}")
                continue
            if not re.fullmatch(pattern, value):
                error(
                    f"secrets/{label} is weak or malformed; "
                    f"run bin/secrets rotate {label}"
                )

    provider_keys = [
        "DEEPSEEK_API_KEY",
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
    ]
    available = [
        name
        for name in provider_keys
        if (secrets / name).is_file()
        and not (secrets / name).is_symlink()
        and (secrets / name).stat().st_size > 0
    ]
    local_only = os.environ.get("AGENT_PALADIN_LOCAL_ONLY") == "1"
    if local_only:
        ok("local-only profile selected; cloud provider keys are not required")
    elif available:
        ok(f"provider keys present: {', '.join(available)}")
    else:
        error(
            "no provider key is set; run bin/secrets set DEEPSEEK_API_KEY (or another provider)"
        )

    for current, dirnames, filenames in os.walk(secrets, followlinks=False):
        for name in [*dirnames, *filenames]:
            path = Path(current) / name
            if path.is_symlink():
                error(f"secret path is a symlink: {path}")
                continue
            if name == ".gitkeep" or path.is_dir():
                continue
            mode = path.stat().st_mode & 0o777
            if mode & 0o077:
                warn(f"secret file is group/world-accessible: {path} ({oct(mode)})")

    if not broker.exists():
        warn("secrets/broker/GITHUB_TOKEN is missing; broker credential injection will be unavailable")


def check_firewall(cfg: dict[str, str]) -> None:
    if cfg.get("SANDBOX_FIREWALL", "on") == "off":
        warn("SANDBOX_FIREWALL=off; the sandbox relies on Docker internal networks only")
        return
    image = "agent-paladin/firewall:1"
    inspect = run(["docker", "image", "inspect", image], capture=True, check=False)
    if inspect.returncode != 0:
        print("INFO  building the firewall probe image")
        build = run(
            [
                "docker",
                "build",
                "-t",
                image,
                "-f",
                str(ROOT / "docker" / "firewall" / "Dockerfile"),
                str(ROOT),
            ],
            capture=True,
            check=False,
        )
        if build.returncode != 0:
            error("could not build the firewall probe image")
            return
    probe = run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--cap-add",
            "NET_ADMIN",
            "--cap-drop",
            "ALL",
            image,
        ],
        capture=True,
        check=False,
    )
    if probe.returncode != 0:
        error(
            "iptables/conntrack is not usable in a container; the sandbox firewall cannot be enforced. "
            "Use --unsafe-no-firewall only if you accept the weaker posture."
        )
        return
    ok("iptables and conntrack work in a container")


def check_runtime(cfg: dict[str, str]) -> None:
    runtime = cfg.get("SANDBOX_RUNTIME", "runc")
    if runtime == "runc":
        return
    runtimes = run(
        ["docker", "info", "--format", "{{json .Runtimes}}"], capture=True, check=False
    ).stdout
    if f'"{runtime}"' in runtimes:
        ok(f"sandbox runtime is available: {runtime}")
    else:
        error(f"sandbox runtime is not configured in Docker: {runtime}")


def main() -> int:
    cfg = config()
    print("== Agent Paladin preflight ==\n")
    check_identity()
    check_command("git")
    check_docker()
    check_platform()
    check_paths(cfg)
    check_bind_mount(cfg)
    check_secrets()
    check_firewall(cfg)
    check_runtime(cfg)
    print("\n")
    if ERRORS:
        print(f"preflight failed with {len(ERRORS)} error(s)")
        return 1
    if WARNINGS:
        print(f"preflight passed with {len(WARNINGS)} warning(s)")
    else:
        print("preflight passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
