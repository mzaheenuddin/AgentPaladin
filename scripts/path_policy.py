"""Shared path policy for snapshot exports and direct-mount audits.

Both the export gate and the post-run audit must agree on which paths can carry
code that the host may later execute. Keeping one policy avoids the previous
situation where a path was blocked by one workflow and silently accepted by
another.
"""

from __future__ import annotations

import fnmatch
from pathlib import PurePosixPath

ALLOWED_ENV_TEMPLATES = frozenset({".env.example", ".env.sample", ".env.template"})

# Any path component in this set is sensitive. These are blocked everywhere in
# the tree, not only at the repository root.
BLOCKED_DIR_NAMES = frozenset(
    {
        ".git",
        ".opencode",
        ".ssh",
        ".aws",
        ".gnupg",
        ".kube",
        ".docker",
        ".agent",
        ".circleci",
        ".husky",
        ".devcontainer",
        "secrets",
    }
)

# Two-component paths (directory, file) that are blocked at any depth.
BLOCKED_PATH_PAIRS = frozenset(
    {
        (".github", "workflows"),
        (".github", "actions"),
        (".vscode", "tasks.json"),
        (".vscode", "launch.json"),
    }
)

BLOCKED_FILE_NAMES = frozenset(
    {
        ".env",
        ".envrc",
        ".npmrc",
        ".pypirc",
        ".netrc",
        ".git-credentials",
        ".gitconfig",
        ".gitmodules",
        ".bash_history",
        ".zsh_history",
        ".python_history",
        ".lesshst",
        ".gitlab-ci.yml",
        ".pre-commit-config.yaml",
        ".travis.yml",
        ".travis.yaml",
        "agents.md",
        "jenkinsfile",
        "credentials.json",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_rsa",
    }
)

BLOCKED_FILE_PATTERNS = (
    ".env.*",
    "opencode.json*",
    "azure-pipelines*.yml",
    "azure-pipelines*.yaml",
    "cloudbuild*.yml",
    "cloudbuild*.yaml",
    "service-account*.json",
    "terraform.tfstate*",
    "terraform.tfvars*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.kdbx",
    "*.jks",
    "*.keystore",
)

RISKY_FILE_NAMES = frozenset(
    {
        "dockerfile",
        "makefile",
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "gemfile",
        "gemfile.lock",
    }
)

RISKY_FILE_PATTERNS = (
    "dockerfile.*",
    "docker-compose*.yml",
    "docker-compose*.yaml",
    "compose*.yml",
    "compose*.yaml",
    "*.sh",
    "*.bash",
    "*.zsh",
    "*.fish",
    "*.ps1",
    "*.bat",
    "*.cmd",
    "*.command",
    "*.tf",
    "*.tfvars",
    ".gitattributes",
    "husky.config.js",
    "lint-staged.config.js",
)


def _name_matches(name: str, patterns: tuple[str, ...] | frozenset[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)


def classify(relative: str) -> tuple[bool, bool]:
    """Return ``(blocked, risky)`` for a repository-relative path.

    Matching is deliberately case-insensitive. On case-insensitive host
    filesystems (macOS/Windows), a path such as ``.GIT/hooks/pre-commit`` can
    refer to the same location as ``.git/hooks/pre-commit``; treating it as
    safe would be an export-gate bypass.
    """
    raw = str(relative).replace("\\", "/")
    path = PurePosixPath(raw)
    parts = tuple(part.casefold() for part in path.parts)
    if not parts or path.is_absolute() or ".." in parts:
        return True, False

    name = parts[-1]
    env_template = name in ALLOWED_ENV_TEMPLATES

    blocked = any(part in BLOCKED_DIR_NAMES for part in parts) or any(
        parts[index : index + 2] in BLOCKED_PATH_PAIRS
        for index in range(len(parts) - 1)
    )

    if not env_template:
        if name in BLOCKED_FILE_NAMES or _name_matches(name, BLOCKED_FILE_PATTERNS):
            blocked = True

    risky = name in RISKY_FILE_NAMES or _name_matches(name, RISKY_FILE_PATTERNS)
    return blocked, risky
