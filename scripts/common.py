"""Shared host-side helpers for the Agent Paladin wrapper scripts."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_STATE_DIR = Path.home() / ".local" / "state" / "agent-paladin"
SAFE_HOOKS_DIR = ROOT / "config" / "git" / "empty-hooks"

_ENV_LINE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$")


class FatalError(RuntimeError):
    pass


def git_safe_env(base: dict[str, str] | None = None) -> dict[str, str]:
    """Return an environment for running Git against untrusted repositories.

    Repository-local configuration and attributes are data supplied by the code
    being inspected. A malicious repository must not be able to make the host
    Git process execute a hook, fsmonitor, pager, credential helper, external
    diff, SSH command, or filter while snapshot/export/audit operations run.
    Inline ``-c`` style configuration below is applied after the repository
    config, so these values win over anything in an untrusted ``.git/config``.
    """
    env = dict(os.environ if base is None else base)
    for key in [key for key in env if key.startswith("GIT_")]:
        env.pop(key, None)

    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_COUNT": "4",
            "GIT_CONFIG_KEY_0": "core.hooksPath",
            "GIT_CONFIG_VALUE_0": str(SAFE_HOOKS_DIR),
            "GIT_CONFIG_KEY_1": "core.fsmonitor",
            "GIT_CONFIG_VALUE_1": "false",
            "GIT_CONFIG_KEY_2": "core.pager",
            "GIT_CONFIG_VALUE_2": "cat",
            "GIT_CONFIG_KEY_3": "core.editor",
            "GIT_CONFIG_VALUE_3": "true",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "/bin/false",
            "GIT_PAGER": "cat",
            "GIT_EDITOR": "true",
            "PAGER": "cat",
            "GIT_OPTIONAL_LOCKS": "0",
        }
    )
    return env


def load_env_file(path: Path, *, override: bool = False) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = _ENV_LINE.match(raw_line)
        if not match:
            continue
        key, value = match.group(1), match.group(2)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key] = os.path.expandvars(value)
    if override:
        os.environ.update(values)
    return values


def config() -> dict[str, str]:
    values: dict[str, str] = {
        "COMPOSE_PROJECT_NAME": "agent-paladin",
        "PROJECT_DIR": os.environ.get("PROJECT_DIR", ""),
        "STATE_DIR": os.environ.get("STATE_DIR", ""),
        "WORKSPACE_MODE": "snapshot",
        "STATE_MODE": "run",
        "SANDBOX_EGRESS": "deny",
        "SANDBOX_ALLOWED_DOMAINS": os.environ.get("SANDBOX_ALLOWED_DOMAINS", ""),
        "SANDBOX_FIREWALL": "on",
        "SANDBOX_RUNTIME": "runc",
        "DEFAULT_MODEL": "deepseek-v4-flash",
        "DLP_ACTION": os.environ.get("DLP_ACTION", "block"),
        "EXTERNAL_MODEL_ACK": "0",
    }
    values.update(load_env_file(ROOT / ".env"))
    values.update(load_env_file(ROOT / "config" / "agent.env"))
    # Explicit process environment wins over files.
    for key in list(values):
        if key in os.environ:
            values[key] = os.environ[key]
    values["ROOT"] = str(ROOT)
    values["AGENT_UID"] = str(os.getuid())
    values["AGENT_GID"] = str(os.getgid())
    if not values.get("PROJECT_DIR"):
        cwd = Path.cwd().resolve()
        if cwd != ROOT:
            values["PROJECT_DIR"] = str(cwd)
    values["PROJECT_DIR"] = str(
        Path(os.path.expandvars(os.path.expanduser(values.get("PROJECT_DIR", "")))).resolve()
        if values.get("PROJECT_DIR")
        else ""
    )
    state = values.get("STATE_DIR") or str(DEFAULT_STATE_DIR)
    values["STATE_DIR"] = str(
        Path(os.path.expandvars(os.path.expanduser(state))).resolve()
    )
    return values


def fail(message: str, code: int = 1) -> "NoReturn":
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(code)


def run(
    command: list[str],
    *,
    capture: bool = False,
    check: bool = True,
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            env=env,
            input=input_text,
            text=True,
            capture_output=capture,
            check=False,
        )
    except FileNotFoundError as exc:
        fail(f"command not found: {command[0]} ({exc})")
    if check and result.returncode != 0:
        if capture and result.stderr:
            fail(result.stderr.strip())
        fail(f"command failed ({result.returncode}): {' '.join(command)}")
    return result


def docker_available() -> bool:
    return shutil.which("docker") is not None


def require_docker() -> None:
    if not docker_available():
        fail("docker is not installed or not on PATH")
    result = run(["docker", "info"], capture=True, check=False)
    if result.returncode != 0:
        fail("cannot reach the Docker daemon; is Docker running?")


def compose_files(egress_mode: str) -> list[Path]:
    files = [ROOT / "compose.yaml"]
    if egress_mode == "allowlist":
        files.append(ROOT / "compose.egress.allowlist.yaml")
    elif egress_mode == "broker":
        files.append(ROOT / "compose.egress.broker.yaml")
    elif egress_mode != "deny":
        fail(f"unknown egress mode: {egress_mode}")
    return files


def generated_dir() -> Path:
    path = ROOT / ".agent" / "generated"
    path.mkdir(parents=True, exist_ok=True)
    try:
        path.chmod(0o700)
    except OSError:
        pass
    return path


def workspace_override_path() -> Path:
    return generated_dir() / "compose.workspace.yaml"


def compose_command(
    files: list[Path], *, project_name: str | None = None
) -> list[str]:
    command = ["docker", "compose"]
    if project_name:
        command.extend(["-p", project_name])
    command.extend(["--project-directory", str(ROOT)])
    for path in files:
        command.extend(["-f", str(path)])
    return command


def parse_env_assignments(values: dict[str, str]) -> dict[str, str]:
    result = dict(os.environ)
    result.update(values)
    return result


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def slugify(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-")
    return slug or "project"


def project_slug(project_dir: Path) -> str:
    """Stable state key for a project path.

    The basename alone is not unique (for example two checkouts named ``app``),
    so include a digest of the resolved absolute path. This prevents shared
    STATE_MODE=project homes from leaking one project's sessions into another.
    """
    resolved = str(project_dir.expanduser().resolve())
    digest = hashlib.sha256(resolved.encode("utf-8", "surrogateescape")).hexdigest()[:12]
    return f"{slugify(Path(resolved).name)}-{digest}"


def ensure_dir(path: Path, mode: int = 0o700) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    try:
        path.chmod(mode)
    except OSError:
        pass
    return path
