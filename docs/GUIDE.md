# Agent Paladin operator guide

This is the detailed runbook for **Agent Paladin** (`agent-paladin`): how to run it day to day,
how to review what the agent produced, and how to tune every security-relevant
configuration without accidentally weakening the design.

`README.md` is the overview and threat model. This guide assumes you have read
it once and now want to operate the stack.

> **The short version:** the agent is untrusted, the workspace is disposable by
> default, provider keys never enter the sandbox, and internet access is an
> explicit, narrow decision. A model provider still receives every prompt and
> every file you send it. No container can change that.

---

## Contents

1. [Mental model](#1-mental-model)
2. [Prerequisites](#2-prerequisites)
3. [First-time setup](#3-first-time-setup)
4. [Daily use](#4-daily-use)
5. [Configuration and tuning](#5-configuration-and-tuning)
6. [Verification](#6-verification)
7. [Recipes](#7-recipes)
8. [Troubleshooting](#8-troubleshooting)
9. [Security review checklist](#9-security-review-checklist)
10. [Command reference](#10-command-reference)
11. [Known limitations](#11-known-limitations)
12. [License and third-party components](#12-license-and-third-party-components)

---

## 1. Mental model

### 1.1 Trust zones

```text
host (trusted) ── secrets, project, state, Docker daemon
   │
   │ bind mounts chosen by bin/agent; no Docker socket
   ▼
sandbox (untrusted) ── OpenCode, shell, repository code
   │
   ├── llm-gateway:24080   authenticated Caddy proxy
   │      └── prompt-dlp:24081   secret-pattern guardrail
   │             └── llm-proxy:24000   LiteLLM, provider keys live here
   │                    └── llm-egress:24128   provider-domain Squid ACL
   │                           └── public internet
   │
   ├── sandbox-egress:24128 (only in allowlist mode) domain ACL
   └── egress-broker:24443 (only in broker mode) human-approved API calls
```

| Zone | Contains | Trust | Main risk |
|---|---|---|---|
| Host | `secrets/`, project checkout, run state, Docker daemon | trusted | Host compromise defeats everything |
| Sandbox | OpenCode, shell, repo, gateway token | untrusted | Prompt injection, destructive edits, data exfiltration |
| Gateway | Caddy, gateway token, LiteLLM master key | trusted, minimal | Token/master-key handling |
| Prompt DLP | regex scanner | trusted, minimal | False positives/negatives |
| LiteLLM | provider API keys | trusted, minimal | Provider keys and prompt contents |
| Egress proxy | Squid domain ACL | trusted, minimal | Domain-level only; no TLS inspection |
| Broker | approval queue + external API credentials | trusted, minimal | Credential injection, approval fatigue |
| Model provider | your prompts/code | third party | Provider sees confidential code |

The sandbox is deliberately on **one** internal network and has **no working
DNS resolver**. `/etc/resolv.conf` points at a dead loopback address, and the
one-shot firewall also drops Docker's embedded resolver at `127.0.0.11` (UDP and
TCP), so a process cannot bypass the dead resolver to resolve or tunnel names.
The only reachable services are the gateway and, when selected, the egress proxy
or broker. `/etc/hosts` is generated per run and contains only those names. The
default route is absent; the one-shot firewall sets default-DROP in the shared
network namespace.

### 1.2 Rules of thumb

- **Never** put a provider key in `config/agent.env`, a Dockerfile, or the
  repository. Keys live only in `secrets/` and Docker secrets.
- **Use `snapshot` unless you have a specific reason not to.** It is the only
  mode that prevents the agent from writing a host Git hook or an OpenCode
  plugin/config into your real checkout.
- **Keep egress allowlists minimal.** A domain allowlist is an exfiltration
  channel to every host under that domain.
- **Treat the model provider as a recipient of the data.** The `confidential`
  profile records that acknowledgement; it does not prevent it.
- **Run `bin/verify` after any security-relevant change.** A configuration that
  looks right but did not reload is a false sense of safety.
- **Do not call `docker compose` directly** for normal operation. The wrappers
  set `SANDBOX_HOME_DIR`, the workspace override, and the per-run environment.

---

## 2. Prerequisites

### 2.1 Required

- Docker Engine or Docker Desktop with a working daemon.
- Docker Compose v2 (`docker compose`, not the old `docker-compose`).
- Git on the host.
- Python 3.10 or newer on the host (the wrappers use modern type syntax).
- A non-root host user. The wrappers use your UID/GID so bind-mounted files
  remain owned by you, not root.
- Enough disk for images, run snapshots, and model state.

### 2.2 Platform notes

**macOS**

- Docker Desktop runs a shared Linux VM. This stack still isolates the agent
  from the macOS filesystem and host network, but a kernel/runtime escape lands
  in the Docker VM, not a dedicated VM.
- Docker Desktop must be allowed to bind-mount `STATE_DIR` (usually under your
  home directory). `bin/preflight` tests this.
- `iptables` is exercised inside the Linux VM; the preflight probe must pass.
- Apple Silicon works; the base images are pinned by multi-arch index digests.

**Linux**

- Rootless Docker or userns-remap is strongly recommended. Without it, a
  runtime escape has your host user's authority.
- The host needs `iptables`/conntrack support for the firewall probe.
- gVisor (`runsc`) is optional; only use it if Docker reports the runtime.

Check the basics:

```sh
docker version
docker compose version
python3 --version
git --version
```

`bin/preflight` performs the environment checks in detail.

---

## 3. First-time setup

Setting up Agent Paladin on your laptop takes about 3 minutes. Run these initial setup steps once from inside the cloned `AgentPaladin` repository root.

### 3.1 Install the CLI globally (Recommended)

Link the `paladin` executable into `~/.local/bin` so you can call `paladin` from any project directory in your terminal:

```sh
./bin/paladin install-cli
```

> [!TIP]
> Ensure `~/.local/bin` is in your shell `PATH`. If it isn't already, add this line to your `~/.zshrc` (macOS default) or `~/.bashrc` (Linux):
> ```sh
> export PATH="$HOME/.local/bin:$PATH"
> ```

Once installed, you can simply type `paladin` instead of `./bin/paladin` or `./bin/agent`.

### 3.2 Initialize and set provider secrets

Agent Paladin generates its own internal cryptographic tokens and stores external provider keys in mode `0600` files on the host (file permissions, not encryption):

```sh
paladin init
paladin secrets set DEEPSEEK_API_KEY
```

`paladin init` generates the internal gateway and LiteLLM master tokens. `paladin secrets set` prompts interactively for your API key without echoing it to your terminal or shell history.

Optional provider keys (if you want Anthropic Claude or OpenAI GPT models):

```sh
paladin secrets set ANTHROPIC_API_KEY
paladin secrets set OPENAI_API_KEY
```

Verify your keys status (values remain hidden):

```sh
paladin secrets
```

Expected output:

```text
GATEWAY_TOKEN            set
LITELLM_MASTER_KEY       set
DEEPSEEK_API_KEY         set
ANTHROPIC_API_KEY        empty
OPENAI_API_KEY           empty
GITHUB_TOKEN             empty
```

*(If a key is empty, models requiring that provider are automatically hidden from the agent's available model list).*

### 3.3 Optional: Custom Configuration (`config/agent.env`)

**You do not need to create or edit `config/agent.env` for standard daily work.** By default:
* Paladin automatically targets whatever project folder you run it from.
* Sessions use secure snapshot mode with all outbound internet blocked.
* Model defaults to DeepSeek V4 Flash.

If you wish to customize global defaults across runs, copy the example:

```sh
cp config/agent.env.example config/agent.env
```

Useful settings in `config/agent.env`:
* `STATE_DIR`: Where snapshots and patches are saved (default: `~/.local/state/agent-paladin`).
* `DEFAULT_MODEL`: Default model alias (e.g. `deepseek-v4-flash`, `claude-sonnet-5-5`, `gpt-6.1-sol`).
* `DLP_ACTION`: `block` (default) or `redact`.

### 3.4 Preflight isolation check

Run the host and container isolation audit:

```sh
paladin preflight
```

This verifies:
* Docker daemon is active and Docker Compose v2 is available.
* Host UID/GID are non-root.
* Container runtime bind-mount permissions work properly.
* Required secret keys exist and are protected.
* iptables and network namespace firewall capabilities function inside the container engine.

### 3.5 Build container images

Build the local hardened images (gateway, sandbox agent, DLP proxy, egress proxies, and firewall):

```sh
paladin build
```

*(The initial build downloads pinned multi-architecture base images for your machine; subsequent builds use Docker cache).*

### 3.6 Verify your setup

Run the complete automated security verification test:

```sh
paladin verify
```

This validates that:
* The sandbox container has dropped all capabilities and root is read-only.
* DNS is dead and unroutable inside the sandbox, including Docker's embedded resolver.
* Metadata service endpoints (`169.254.169.254`) and the host network bridge are unreachable.
* Secret canaries and DLP rules are actively enforced.

---

## 4. Daily use

### 4.1 Working across multiple projects on your laptop

Agent Paladin is designed specifically for developers who juggle multiple projects. **You can launch Paladin from any repository on your machine:**

```sh
# Switch to any project directory
cd ~/projects/my-web-app

# Launch Paladin directly
paladin
```

When run from any project directory:
1. **Automatic Directory Detection**: Paladin detects your current working directory and creates a sanitized snapshot.
2. **Zero Pollution**: In the default snapshot workflow, your host `.git`
   history, `.env` files, and credentials are never exposed or altered. Direct
   modes are opt-in and mask credential files/directories by default.
3. **Dedicated Run State**: The session state, chat logs, and changes are kept in an isolated run folder under `~/.local/state/agent-paladin/runs/<run-id>/`.

To target a project from elsewhere, pass `--project`:

```sh
paladin --project ~/projects/another-repo
```

### 4.2 Interactive coding session

```sh
cd ~/projects/my-app
paladin
```

This launches the OpenCode terminal interface inside the hardened container.
* Type your prompts, ask for features, refactorings, or bug fixes.
* The agent can create files, run tests, and make commits inside its disposable sandbox clone.
* To switch models on the fly inside the session, use `/models`.

When you are done, exit OpenCode (`Ctrl+C` or type `/exit`). Paladin automatically generates a git diff patch and a safety audit report.

### 4.3 Reviewing and applying changes

After an agent session finishes, review what the agent did before letting anything touch your host repository:

```sh
# 1. Inspect the patch and safety findings
paladin export

# 2. Check changes.patch, changes.stat, and report.json in the reported run directory.

# 3. Apply reviewed changes to your working project:
paladin export --apply
```

The export gate automatically guards your host:
* Rejects modified `.git/` hooks, submodules, and `.opencode/` configs.
* Rejects added `.env` credentials or secrets.
* Rejects blocked CI/CD workflows (`.github/workflows`, `.gitlab-ci.yml`, `.circleci`, Jenkinsfile).
* Flags risky files (like Dockerfiles, Makefiles, or install scripts), requiring `paladin export --apply --allow-risky`.

### 4.4 One-shot instructions

You can run one-shot tasks without entering an interactive shell:

```sh
cd ~/projects/my-app
paladin --run "Fix the type error in src/auth.ts and run npm test"
```

To use a different model for a specific task:

```sh
paladin --model claude-sonnet-5-5 --run "Refactor the database queries in db/users.go"
```

### 4.5 Inspecting the sandbox shell

If you want an interactive bash shell inside the container to test environment behavior or run manual commands:

```sh
paladin shell
```

This starts the same sandbox with `/bin/bash` instead of the OpenCode
entrypoint. It is useful for network, filesystem, and Git checks.

Important: the normal entrypoint is bypassed, so `LITELLM_GATEWAY_KEY` is not
exported into this shell. For gateway tests, read the scoped token directly:

```sh
TOKEN="$(cat /run/secrets/gateway_token)"
curl --noproxy '*' -H "Authorization: Bearer $TOKEN" \
  http://llm-gateway:24080/v1/models
```

`paladin shell` uses the same snapshot and firewall setup as a regular session. It is useful for network, filesystem, and Git tests inside the container.

### 4.6 Direct mode and direct-commit

Snapshot is the default and strongly recommended. The other modes are for workflows that genuinely require immediate in-place writes to your working tree:

**Direct** (`--workspace direct`):

```sh
paladin --workspace direct
```

- Host project mounted read-write.
- `.git` mounted read-only; a `.git` symlink is refused. Nested `.git`
  directories/files (submodules or otherwise) are also mounted read-only.
- Existing `.opencode/`, nested `opencode.json*`/`AGENTS.md` are mounted
  read-only. Missing root control-plane paths (`.opencode/`, `opencode.json`,
  `opencode.jsonc`, `AGENTS.md`) are mounted as empty read-only placeholders so
  the agent cannot create them and have OpenCode hot-reload new behavior
  mid-session.
- Credential files such as `.env*`, `.npmrc`, `.pypirc`, `.netrc`,
  `.git-credentials`, `credentials.json`, `service-account*.json`,
  Terraform state, private-key files, and keystores are replaced with empty
  files by default, so the agent cannot read them.
- Credential stores such as `secrets/`, `.ssh/`, `.aws/`, `.gnupg/`, `.kube/`,
  `.docker/`, `.gitconfig`, and shell histories are always replaced with empty
  directories/files.
- After you review the direct-mode risk, `--allow-secrets` exposes the
  credential *files* read-only (not the credential directories) so a local app
  can start. Once this flag is used, the agent can read those files; treat their
  contents as exposed to the model and rotate anything sensitive afterwards.
- Agent cannot commit.
- Post-run `paladin audit` reports changed high-risk paths (including ignored
  files), unsafe symlinks, and secret patterns.

**Direct-commit** (`--workspace direct-commit`):

```sh
paladin --workspace direct-commit
```

- Host project and `.git` writable (a `.git` symlink or any symlink inside
  `.git` is refused).
- `.git/hooks`, `.git/info`, `.git/modules`, `.git/worktrees`,
  `.git/objects/info`, and `.git/config` read-only when they already exist.
  Credential-store masking from direct mode also applies.
- `core.hooksPath` still points at an empty directory, so a hook cannot execute.
- Commits are allowed. Nested `.git` directories/files are mounted read-only.
- Host Git parses agent-produced objects. This is reduced assurance; snapshot
  remains the safer mode. The post-run audit fails if any symlink exists inside
  `.git`; do not run host-side Git on the repository until such links are
  reviewed and removed.

Both direct modes require a normal `.git` directory. A worktree (`.git` file)
is not supported; use snapshot mode.

### 4.7 Installing packages

Use the `install` profile and a minimal domain list:

```sh
paladin --profile install \
  --allow registry.npmjs.org,pypi.org,files.pythonhosted.org
```

or set a default list in `config/agent.env`:

```dotenv
SANDBOX_ALLOWED_DOMAINS=registry.npmjs.org,pypi.org,files.pythonhosted.org
```

Then run the install inside the OpenCode session or a `paladin shell` session. The
proxy environment variables are set automatically.

This is **domain-level** access, not package integrity. An allowed registry can
serve a malicious package. Prefer lockfiles and script-disabled installs where
possible:

```sh
npm ci --ignore-scripts
pip install --only-binary=:all: -r requirements.txt
```

### 4.8 Calling an external API with approval

Configure the broker first (section 5.5), then:

```sh
paladin --profile api
```

Inside the sandbox, send a request to the broker:

```sh
curl -sS -X POST http://egress-broker:24443/request \
  -H 'Content-Type: application/json' \
  -d '{
    "method": "GET",
    "url": "https://api.github.com/zen",
    "headers": {"User-Agent": "agent-paladin"}
  }'
```

The request blocks while waiting for approval. On the host:

```sh
paladin pending
paladin approve <request-id>
# or
paladin deny <request-id>
```

The broker shows a redacted body preview. Approval is one-shot and expires after
`approval_timeout_seconds`. The sandbox never receives the external API
credential; the broker injects it after approval.

### 4.9 Local model (Ollama)

The local profile does not require a cloud provider key. Pull the model once,
then start the session:

```sh
paladin ollama pull qwen3-coder
paladin ollama list
paladin --profile local
```

`bin/ollama` starts the optional Ollama service on `inference_net`, starts a
dedicated `ollama-egress` proxy with a model-registry-only allowlist, and runs
the Ollama CLI. Model downloads go through that proxy; Ollama is not attached to
the public network directly. The sandbox cannot reach Ollama; only LiteLLM can.
If your pulled model has a different name, update the `upstream` and alias in
`config/models.json`, then re-render and reload.

Local models are the only way to avoid sending code to an external provider.
They are usually weaker at agentic coding; do not pretend otherwise.

If confidential code must use an external model, the only supported path is:

```sh
paladin --profile confidential --ack-external-model
```

or set `EXTERNAL_MODEL_ACK=1` in `config/agent.env`. The profile still uses a
sanitized snapshot and no sandbox egress, but it does **not** prevent the model
provider from receiving the code. That is a provider-trust decision, not a
technical boundary. The acknowledgement is recorded in the run manifest.

### 4.10 Non-Git projects

- Snapshot mode works without Git. It walks the tree, applies the hard-coded
  exclusions, creates a fresh Git repository inside the run, and scans it.
- Direct modes require a Git repository and will fail fast.
- `bin/export --apply` requires the target project to be a Git repository. For a
  non-Git target, initialize one first or apply the patch manually after review.

If the source is not a Git repository, ignored-file rules from `.gitignore` are
not available; the hard-coded exclusions still apply, but review the snapshot
file list in `snapshot.json` before trusting it.

### 4.11 State, sessions, and multiple projects

Default `STATE_MODE=run` gives every run a fresh home:

```text
STATE_DIR/runs/<run-id>/home
STATE_DIR/runs/<run-id>/workspace
STATE_DIR/runs/<run-id>/export
STATE_DIR/runs/<run-id>/manifest.json
```

This is the strongest privacy default: later runs cannot read earlier session
logs. It also means `--continue` cannot resume a session from a previous run.

If you want continuity:

```dotenv
STATE_MODE=project
```

Then the run's `home` is a symlink to:

```text
STATE_DIR/projects/<project-slug>/home
```

Later runs for the same project share that home. This lets OpenCode session
listing/continuation work, but it also means a later agent can read earlier
session data, including code and prompts. Treat that directory as sensitive.

To use multiple project directories without editing the file:

```sh
./bin/agent --project /path/to/other/project
```

Use one `STATE_DIR` per trust boundary if you want strong separation.

### 4.12 Stop and clean up

```sh
./bin/down                 # stop containers and networks
./bin/down --volumes       # also remove the Ollama volume (destructive)
./bin/logs                 # follow all service logs
./bin/logs llm-proxy       # follow one service
./bin/clean                # keep the five newest runs
./bin/clean --all          # delete all run directories
```

`bin/clean` deletes exported patches too. If a patch matters, copy it out of
the run directory first.

---

## 5. Configuration and tuning

### 5.1 Configuration map

| File | Controls | When it takes effect |
|---|---|---|
| `config/agent.env` | project, state, default workspace/egress, firewall, runtime, DLP action, default model, external-model ack | Next `bin/agent` / `bin/preflight` / `bin/verify` |
| `.env` | Compose project name and any values Compose reads; loaded by the wrappers too | Next wrapper invocation |
| `config/models.json` | aliases, upstream models, provider secrets, limits, capabilities, local-only flag | `bin/models` (or next `bin/agent`) then reload LiteLLM |
| `config/opencode/base.json` | OpenCode provider, policies, permissions, instructions, defaults | Next `bin/agent` render/run |
| `config/opencode/AGENTS.md` | Global sandbox operating instructions | Next run |
| `config/egress/provider-allow.txt` | Domains LiteLLM may reach through `llm-egress` | Recreate `llm-egress` (`bin/reload`) |
| `config/egress/provider-deny.txt` | Provider domains the sandbox proxy blocks and the wrapper refuses in sandbox allowlists | Recreate `sandbox-egress`; used at next `bin/agent` validation |
| `config/broker/config.json` | Broker hosts, approval, credentials, headers, limits | Recreate `egress-broker` (`bin/reload`) |
| `scripts/dlp_patterns.py` | Secret patterns for host scan, prompt DLP, broker DLP | Host scripts immediately; containers after `bin/build` + reload |
| `scripts/snapshot.py` | Snapshot inclusion/exclusion policy | Next `bin/agent` |
| `scripts/secret_scan.py` | Host scan exclusions, file limits, entropy | Next scan/run |
| `scripts/export_patch.py` | Export blocked/risky paths | Next export |
| `scripts/audit_changes.py` | Direct-mode audit policy | Next audit |
| `docker/egress/squid.conf` | Proxy ports, ACL order, logging | Rebuild `llm-egress`/`sandbox-egress` |
| `docker/firewall/lockdown.sh` | Sandbox netns firewall | Rebuild firewall; next run applies it |
| `compose.yaml` | Services, networks, IPs, secrets, resource limits | Rebuild if needed; next wrapper run |
| `config/git/gitconfig` | Git hooks/config/credential hard rules | Next run |
| `secrets/*` | Provider keys, gateway token, master key, broker token | Recreate the consuming service |
| `bin/agent` | Wrapper orchestration and protected-path lists | Code change; next run |

**Reload matrix:**

| Change | Action |
|---|---|
| `config/models.json` | `./bin/models`, then `./bin/reload` (or a new run) |
| `config/broker/config.json` | `./bin/reload` |
| `config/egress/provider-allow.txt` | `./bin/reload` |
| `config/egress/provider-deny.txt` | `./bin/reload` (sandbox proxy) |
| `config/opencode/base.json` or `AGENTS.md` | Next `./bin/agent`; no rebuild |
| `scripts/dlp_patterns.py` | `./bin/build`, then `./bin/reload` |
| `docker/egress/squid.conf` | `./bin/build`, then `./bin/reload` |
| `docker/firewall/lockdown.sh` | `./bin/build`; next run applies it |
| `compose.yaml` topology/resources | Rebuild if Dockerfile changed; next `./bin/agent` |
| Provider key file | Recreate `llm-proxy` (`./bin/reload` or new run) |
| `GATEWAY_TOKEN` | Recreate `llm-gateway` and start a new sandbox |
| `LITELLM_MASTER_KEY` | Recreate `llm-gateway` and `llm-proxy` |

`bin/reload` uses the latest run's manifest and Compose files, recreates the
long-lived proxy services, and refuses to run while a sandbox container is
active unless you pass `--force`. It does not build images. For a code change,
run `./bin/build` first. For a topology change, start a new run.

### 5.2 Project and state paths

`PROJECT_DIR`:

- Must be a directory; it is expanded and resolved.
- In snapshot mode, it is read to produce a copy. In direct modes, it is the
  bind-mounted workspace.
- Can be overridden per run with `--project`.

`STATE_DIR`:

- Holds run workspaces, homes, manifests, exports, and project-shared state.
- Is created `0700`; secret files are separate under `secrets/`.
- Should be local disk, not a network share. Network filesystems can break
  ownership, locking, and performance.
- Contains sensitive data: code snapshots, session logs, patches, model output.
  Back it up or delete it with that in mind.

`COMPOSE_PROJECT_NAME`:

- Used for container/network names. Change it if another stack uses the same
  name.
- The stack uses a fixed `172.31.240.0/24` subnet. Do not run two instances
  simultaneously without changing the subnet (section 5.10).

`STATE_MODE`:

- `run` — fresh home per run; strongest privacy; no cross-run sessions.
- `project` — shared home per project; continuity; later runs can read earlier
  session data.

### 5.3 Workspace mode tuning

Set the default in `config/agent.env`:

```dotenv
WORKSPACE_MODE=snapshot
```

Override per run:

```sh
./bin/agent --workspace direct
./bin/agent --workspace direct-commit
```

If you pass an explicit `--profile`, its workspace/egress defaults take
precedence over `config/agent.env`; `--workspace` and `--egress` still win over
the profile.

#### Snapshot exclusions

The lists live in `scripts/snapshot.py`:

- `EXCLUDED_NAMES` — directory/file names excluded anywhere, such as `.git`,
  `.ssh`, `.opencode`, `secrets`, `node_modules`, build output, and caches.
- `EXCLUDED_PATTERNS` — filename/path globs such as `.env`, `.env.*`, `.envrc`,
  `.npmrc`, `*.pem`, `*.key`, `credentials.json`, `service-account*.json`,
  `terraform.tfstate*`, logs, and SQLite files.
- `ALLOWED_ENV_TEMPLATES` — `.env.example`, `.env.sample`, `.env.template`.

For a Git source, only tracked files plus untracked non-ignored files are
considered. `.gitignore` therefore affects what is copied. For a non-Git
source, `_walk_files` uses `EXCLUDED_NAMES` and then the same pattern checks.

To exclude an additional project-specific file or directory, add it to the
appropriate list and re-run. Keep the policy narrow; excluding a whole
directory that contains credentials is better than trying to scan it. Examples:

```python
EXCLUDED_NAMES = {
    # ...
    "fixtures/private",
    "generated",
}

EXCLUDED_PATTERNS = [
    # ...
    "*.kdbx",
    "config/production.*",
]
```

Do not add `.env` to an allowlist. The snapshot is not a secret manager.

`symlink` handling:

- Relative symlinks whose resolved target stays inside the project are copied as
  symlinks.
- Absolute symlinks and symlinks escaping the project are **skipped** with a
  warning; the run continues. Review `snapshot.json` → `symlink_warnings`.
- The export gate separately rejects absolute/escaping symlinks among changed
  files.

#### Host secret scanning

`scripts/secret_scan.py` scans snapshot files, direct-mode trees, changed files
for export, and can be run directly:

```sh
./bin/scan /path/to/project
./bin/scan --include-entropy /path/to/project
./bin/scan --json /path/to/project
```

It skips large files (default 2 MiB), binary-looking files, VCS/dependency
directories, and common binary suffixes. It uses the shared patterns in
`scripts/dlp_patterns.py`.

If the scan produces a false positive:

1. Look at the rule name and preview.
2. If it is a real secret, remove/rotate it; do not bypass the scan.
3. If it is a test fixture, use an obvious placeholder such as
   `example`, `dummy`, `fake`, `redacted`, or a `<...>` placeholder. Those
   markers are ignored by the scanner.
4. If a legitimate value must remain, refine the pattern or add a narrowly
   scoped placeholder marker in `dlp_patterns.py`. Rebuild the containers that
   copy that file and re-run verification.

`bin/agent` in direct mode scans the whole tree, not just changed files. Use
`--allow-secrets` only when you have reviewed the findings and accept that
credential files will be visible read-only in the sandbox. Credential
directories remain masked even with the flag. It does not disable the post-run
audit.

#### Export and audit policy

`scripts/export_patch.py` uses the shared `scripts/path_policy.py`:

- Blocked paths — never export; includes VCS, nested OpenCode/agent config,
  credential stores, keys, CI/DevOps/editor task files, hooks, and secrets.
- Risky paths — require `--allow-risky`; includes scripts, Dockerfiles,
  Compose files, Makefiles, package manifests, Terraform, and `.gitattributes`.
- Env templates are allowed even though `.env*` is blocked.

`scripts/audit_changes.py`:

- The policy is shared with the export gate in `scripts/path_policy.py`; both
  workflows block the same nested configuration, credential, CI, hook, and
  executable paths, case-insensitively.
- It scans changed files for secret patterns and unsafe symlinks.
- It also includes non-bulk ignored files in the audit, so an ignored `.env` or
  secrets file created during a direct run is reported.
- It exits nonzero if it finds blocked paths, unsafe symlinks, or secrets.
  `bin/agent` now returns that nonzero post-run status when the agent itself
  exited successfully, so automation cannot mistake a failed audit for a clean
  session.

If your project has additional high-risk paths, update the shared policy in
`scripts/path_policy.py` (or add project-specific patterns in both code paths).
For example, infrastructure directories and deployment manifests:

```python
# Edit scripts/path_policy.py instead of duplicating lists here.
```

Keeping one shared policy prevents a path from being blocked in one workflow
and silently accepted in another.

#### Choosing a mode

| Situation | Recommended |
|---|---|
| Untrusted repo, prompt-injected content, new dependency | `snapshot` |
| Normal coding, review before applying | `snapshot` |
| Need IDE watchers or immediate host edits | `direct`, accept residual risk |
| Must commit from inside the sandbox | `direct-commit`, accept Git parsing risk |
| Non-Git project | `snapshot` |
| Highly sensitive code | `snapshot` + `deny` + local model, or accept provider exposure with `confidential` |

### 5.4 Egress modes

#### Selection and precedence

Default is `SANDBOX_EGRESS=deny`:

- No sandbox egress except `llm-gateway:24080` and loopback.
- No DNS, no metadata endpoint, no host bridge.

Per-run:

```sh
./bin/agent --egress deny
./bin/agent --egress allowlist --allow registry.npmjs.org
./bin/agent --egress broker
```

Precedence:

1. `--egress` (explicit flag) wins.
2. An explicit `--profile` / `PROFILE` selects the profile's egress.
3. Otherwise `SANDBOX_EGRESS` from `config/agent.env` applies.

For allowlist domains:

1. `--allow` entries win and **replace** `SANDBOX_ALLOWED_DOMAINS`.
2. If no `--allow`, `SANDBOX_ALLOWED_DOMAINS` is used.
3. If both are empty, the run fails rather than starting an empty proxy.

`--allow` is ignored outside allowlist mode; the wrapper prints a warning.

#### Domain syntax and validation

The wrapper accepts hostnames such as:

```text
registry.npmjs.org
.example.com
```

and rejects:

- URLs (`https://...`), paths, ports, wildcards (`*`).
- IP addresses.
- `localhost`, `.local`, `.internal`, `.localhost`.
- Any domain equal to or under a provider in
  `config/egress/provider-deny.txt` (for example `.deepseek.com`).

A leading dot is Squid suffix syntax: `.example.com` covers `example.com` and
all subdomains. Do not list both `.example.com` and `api.example.com` in the
same Squid ACL; Squid treats that as a fatal configuration error. The sandbox
allowlist validator lets a leading-dot entry absorb narrower entries and rejects
ambiguous exact parent/child pairs with a request to use a broader leading-dot
entry. The provider allowlist is a plain Squid file and is not normalized for
you.

#### What the proxy does and does not do

`docker/egress/squid.conf`:

- Listens on `24128`.
- Allows only HTTPS port `443` (`CONNECT` to 443; plain HTTP port 80 is denied).
- Denies private, loopback, link-local, and metadata ranges.
- Denies `provider-deny.txt`.
- Allows only names in the generated allowlist.
- Denies everything else.
- The sandbox resolver itself is dead and Docker's embedded resolver is dropped
  by the firewall; the proxy does not provide DNS-over-HTTP or a resolver.
- Does not cache; strips query terms from access logs; disables `Via` and
  `Forwarded-For`.

It does **not** inspect TLS bodies. It cannot enforce paths, HTTP methods, or
response content. An allowed domain can be used as an exfiltration channel
through URLs, query strings, uploads, or user content. Keep the list small and
avoid domains that host arbitrary user content (for example, broad paste or
repository-hosting domains) unless that is the explicit workflow.

#### Common allowlists

Use only what the project needs:

| Ecosystem | Domains |
|---|---|
| npm | `registry.npmjs.org` |
| PyPI | `pypi.org`, `files.pythonhosted.org` |
| Go modules | `proxy.golang.org`, `sum.golang.org` |
| crates.io | `index.crates.io`, `static.crates.io` |
| Debian | `deb.debian.org`, `security.debian.org` |
| Alpine | `dl-cdn.alpinelinux.org` |
| GitHub releases / raw | Prefer the broker or vendored artifacts; domain allowlisting `github.com`/`raw.githubusercontent.com` is broad |

`--allow` accepts comma-separated values and can be repeated:

```sh
./bin/agent --profile install \
  --allow registry.npmjs.org \
  --allow pypi.org,files.pythonhosted.org
```

#### Provider egress (LiteLLM → internet)

`config/egress/provider-allow.txt` is mounted into `llm-egress`, which LiteLLM
uses via `HTTP_PROXY`/`HTTPS_PROXY`. It currently allows the DeepSeek,
Anthropic, OpenAI, and OpenRouter domains.

When adding a provider:

1. Add its API domain to `config/egress/provider-allow.txt`, using a leading dot
   if you want subdomains.
2. Add the same domain to `config/egress/provider-deny.txt`, so the sandbox
   proxy and the allowlist validator refuse direct access.
3. Add the provider/model and secret (section 5.6).
4. `./bin/reload` to recreate `llm-egress` and `llm-proxy`.
5. Test with a real request; watch `bin/logs llm-egress` and `llm-proxy`.

Do not list both a domain and its subdomain in `provider-allow.txt`; Squid will
fail to start with a “Bungled ... acl” message. Check its logs after editing.

`provider-deny.txt` is used by `sandbox-egress` and by `bin/agent` validation.
It is not mounted into `llm-egress`; if you want to block a provider at the
LiteLLM proxy as well, remove it from `provider-allow.txt` instead.

#### Testing allowlist egress

Start an allowlist run and use the shell:

```sh
./bin/agent --profile install --allow registry.npmjs.org --shell
```

Inside:

```sh
# Allowed
curl --noproxy '*' -x http://sandbox-egress:24128 -sS -o /dev/null \
  -w '%{http_code}\n' https://registry.npmjs.org/

# Denied (expect a 403 CONNECT response)
curl --noproxy '*' -x http://sandbox-egress:24128 -sS -o /dev/null \
  -w '%{http_code}\n' https://example.com/

# Direct egress must fail
curl --noproxy '*' --connect-timeout 3 -sS -o /dev/null https://1.1.1.1
```

The proxy logs hostnames and paths; query terms are stripped.

### 5.5 Broker tuning

The broker is a small, trusted service. Treat its config and secrets as
security-sensitive code.

#### Full configuration reference

`config/broker/config.json`:

| Key | Default | Meaning |
|---|---|---|
| `approvable_domains` | `[]` | Hosts the sandbox may ask to reach. Exact hostname or leading-dot suffix; `*` is ignored. Empty means all requests are denied. |
| `approval_required` | `true` | If false, allowed hosts forward without human approval. Not recommended. |
| `approval_timeout_seconds` | `300` | How long a request waits for approval before returning 408. |
| `allowed_methods` | `GET, POST, PUT, PATCH, DELETE` | HTTP methods accepted. |
| `allowed_ports` | `[443]` | Upstream ports; broker only uses HTTPS. |
| `auto_approve_domains` | `[]` | Hosts that bypass the approval prompt. Use only for low-risk, read-only APIs. |
| `allowed_request_headers` | `accept, content-type, user-agent` | Request headers forwarded to the upstream API. Everything else is stripped. |
| `blocked_request_headers` | `[]` | Extra deny list, applied after the allowlist. |
| `credentials` | `{}` | Host → `{secret_file, header, prefix}` injection map. |
| `max_request_bytes` | `1048576` | Request body limit. |
| `max_response_bytes` | `5242880` | Upstream response limit. |
| `max_pending_requests` | `64` | Queue limit; further requests receive 429. |
| `request_timeout_seconds` | `30` | Socket/read timeout; prevents slowloris and stalled body reads. |

The request wrapper body is JSON:

```json
{
  "method": "GET",
  "url": "https://api.github.com/zen",
  "headers": {"User-Agent": "agent-paladin"},
  "body": "optional string or JSON object"
}
```

Only `https` is accepted. Credentials in the URL and URL userinfo are rejected.
The target must resolve only to public addresses.

#### Add an API host

For an unauthenticated API:

```json
{
  "approvable_domains": ["api.example.com"],
  "approval_required": true
}
```

Then:

```sh
./bin/reload
./bin/agent --profile api
```

Test from inside the sandbox. The host approval step is the actual control; do
not add `auto_approve_domains` unless you have a specific automation reason.

#### Add a credentialed API

Example: GitHub token injection.

1. Put the token in the broker secret file, mode `0600`:

   ```sh
   ./bin/secrets set GITHUB_TOKEN
   ```

   The helper knows `GITHUB_TOKEN` and writes
   `secrets/broker/GITHUB_TOKEN`. For a different broker token, see the note
   below.

2. Add the host and credential to `config/broker/config.json`:

   ```json
   {
     "approvable_domains": ["api.github.com"],
     "allowed_request_headers": ["accept", "content-type", "user-agent"],
     "credentials": {
       "api.github.com": {
         "secret_file": "/run/secrets/github_token",
         "header": "Authorization",
         "prefix": "Bearer "
       }
     }
   }
   ```

3. Ensure the secret is mounted into the broker container. The current
   `compose.egress.broker.yaml` already mounts `github_token`. For another
   secret, add it to both the top-level `secrets:` block in `compose.yaml` and
   the `egress-broker.secrets` list, with a target file name that matches the
   `secret_file` path.

4. `./bin/reload`.

5. Verify with `./bin/egress-pending` plus an approval. The broker logs
   `request_forwarded` with the status; the token is never returned to the
   sandbox.

Adding a new broker secret today requires a small code/Compose edit because
`bin/secrets` only knows `GITHUB_TOKEN`. Either add the name to `BROKER_KEYS` in
`bin/secrets`, or create the file manually with restrictive permissions:

```sh
umask 077
read -rsp 'Broker token: ' TOKEN; printf '%s\n' "$TOKEN" > secrets/broker/MY_API_TOKEN
chmod 600 secrets/broker/MY_API_TOKEN
unset TOKEN
```

Then wire the Compose secret target (`/run/secrets/my_api_token`) and the
`secret_file` path in the broker config. Recreate the broker.

#### Headers and API quirks

Many APIs require custom headers (`X-GitHub-Api-Version`, `Accept` media types,
`Idempotency-Key`, and so on). Add only the exact headers to
`allowed_request_headers`; do not add `authorization`, `cookie`, or `x-api-key`
because the broker is supposed to own credentials. If an API requires a
signature computed over the body, the broker cannot sign it without a code
change; do not try to smuggle a signature through an allowed generic header
unless you understand the trust implications.

#### Approval operations

- `./bin/egress-pending` lists pending requests with a redacted body preview.
- `./bin/egress-approve <id>` forwards once.
- `./bin/egress-deny <id>` rejects.
- The request blocks until a decision or timeout. If the caller times out, the
  pending entry is removed; a late approval returns 404.
- The admin API listens on `127.0.0.1:24900` inside the broker container. The
  sandbox cannot reach it; the host reaches it through `docker compose exec`.
- `bin/egress` only works when the latest run used the broker. If you start a
  new run with a different egress mode, approvals for the old run are not
  addressable through the helper.

#### Broker limitations

- It enforces host, method, port, and body size; it does not understand API
  schemas or paths.
- It scans request bodies, URLs, and headers for secret patterns, and scans
  textual responses; detected response values are redacted. Compressed request
  bodies are rejected rather than forwarded uninspected.
- It resolves the target, rejects any non-public address, and pins the verified
  public IP for the actual TLS connection; the check is repeated at forward
  time, so DNS rebinding between validation and dispatch is blocked.
- Human approval is a control only if the human reads the preview. Do not
  approve from muscle memory.
- The broker holds external credentials. A broker compromise is a credential
  compromise.

### 5.6 Models and providers

`config/models.json` is the source of truth for aliases. The renderer produces
LiteLLM's model list and OpenCode's provider model definitions.

#### Model entry fields

| Field | Required | Meaning |
|---|---|---|
| `alias` | yes | Internal model name used by OpenCode and LiteLLM. Keep it stable. |
| `name` | no | Display name in OpenCode. |
| `provider` | yes | Provider family for documentation/metadata. |
| `upstream` | yes | LiteLLM model string, for example `deepseek/deepseek-v4-flash`. |
| `secret` | no | Secret file name under `secrets/`; omit/null for local models. |
| `apiBase` | no | Override base URL for OpenAI-compatible or local providers. |
| `limit.context` | recommended | Context window advertised to OpenCode. |
| `limit.output` | recommended | Max output tokens advertised to OpenCode. |
| `capabilities` | recommended | Tool/image/text capabilities. |
| `cacheFormat` | no | `anthropic` for Claude prompt caching through LiteLLM. |
| `localOnly` | no | Excluded unless the local profile or `--include-local` is used. |

Availability rule: a model is omitted when its `secret` file is missing or
empty. Local models have no secret. If the requested default is unavailable,
the renderer falls back to `config/models.json`'s default, then the first
available alias, and prints a warning.

#### Add or change a model (same provider)

1. Edit `config/models.json`.
2. Keep the alias consistent with what you will type after `--model`.
3. Run `./bin/models` and inspect `.agent/generated/available.json`.
4. Run `./bin/reload` to restart LiteLLM with the new config, or start a new run.
5. Test:

   ```sh
   ./bin/agent --model my-new-alias --run "Reply with OK"
   ```

If LiteLLM does not know the alias, check `llm-proxy` logs and confirm
`./bin/models` wrote the alias to `.agent/generated/litellm.json`.

#### Add a new provider

This is an extension, not a pure config change. The steps are:

1. Add the provider secret file, mode `0600`:

   ```sh
   umask 077
   read -rsp 'Provider key: ' KEY; printf '%s\n' "$KEY" > secrets/MY_PROVIDER_API_KEY
   chmod 600 secrets/MY_PROVIDER_API_KEY
   unset KEY
   ```

   `bin/secrets list` will not show unknown names unless you add the name to
   `OPTIONAL_PROVIDER_KEYS` in `bin/secrets`. Also add it to `SECRET_FILES` in
   `bin/agent` and to `provider_keys` in `scripts/preflight.py`; otherwise
   automatic secret initialization/preflight will not know about it. If it is
   the only provider key, add it before running `bin/preflight`.

2. Add the secret to `compose.yaml` under the top-level `secrets:` block and to
   `llm-proxy.secrets`:

   ```yaml
   secrets:
     my_provider_api_key:
       file: ./secrets/MY_PROVIDER_API_KEY

   services:
     llm-proxy:
       secrets:
         - my_provider_api_key
   ```

3. Export the key in `docker/litellm/entrypoint.sh`:

   ```sh
   if [ -f /run/secrets/my_provider_api_key ]; then
     MY_PROVIDER_API_KEY="$(cat /run/secrets/my_provider_api_key)"
     export MY_PROVIDER_API_KEY
   fi
   ```

4. Add the API domain to `config/egress/provider-allow.txt` and
   `config/egress/provider-deny.txt`.

5. Add a model entry in `config/models.json` with `secret:
   "MY_PROVIDER_API_KEY"` and the correct `upstream`/`apiBase`.

6. `./bin/build` (entrypoint changed), `./bin/models`, then `./bin/reload`.

7. Run `./bin/verify` and a real request.

If the provider is OpenAI-compatible, LiteLLM often uses
`openai/<model>` plus `apiBase`; verify the exact upstream string in LiteLLM's
documentation for your provider. Do not guess a model name.

#### Model lifecycle

- Changing a provider key requires recreating `llm-proxy` because the entrypoint
  exports it at startup.
- Changing a model alias or config requires a LiteLLM restart.
- Changing `DEFAULT_MODEL` only changes the default selected for new
  OpenCode configs; existing runs keep their rendered config.
- In an interactive session, switch among rendered aliases with the model
  picker. If an alias is missing, it was not available at render time.

### 5.7 DLP tuning

The DLP is intentionally pattern-based. It is a guardrail against accidental
leaks, not a boundary against an agent that encodes, splits, or steganographically
hides data.

#### Where it runs

- `scripts/secret_scan.py` — host scanner for snapshots, direct trees, and
  export.
- `docker/prompt-dlp/app.py` — scans JSON request bodies before LiteLLM.
- `docker/egress-broker/app.py` — scans method, URL, headers, and body before
  approval.

All three import `scripts/dlp_patterns.py` (the containers copy it into the
image).

#### Patterns and placeholders

`_PATTERNS` includes private keys, AWS access/secret keys, GitHub tokens,
`sk-` provider keys, Stripe live keys, Slack tokens, Google API keys, JWTs,
database URLs with passwords, generic credential assignments, and
`CANARY_...` test tokens.

`PLACEHOLDER_MARKERS` suppresses matches containing values such as `example`,
`sample`, `dummy`, `fake`, `placeholder`, `changeme`, `redacted`, `your_`,
`<...>`, `${...}`, `xxxx`, `****`, and `not-a-real`. This is why fixtures such
as `sk-test-example` do not block a snapshot. Do not put a marker in a real
secret.

#### Actions

`DLP_ACTION=block` (default) returns HTTP 403 with `type: dlp_block` at the
prompt DLP. `DLP_ACTION=redact` replaces detected values with
`[REDACTED:<rule>]` and forwards the request. Redaction is only applied to
valid JSON; invalid JSON is blocked. Redaction changes the prompt and can make
the model's answer less useful. Compressed or chunked request bodies are
rejected with 415 because the pattern scanner cannot inspect them safely.

The broker always blocks; it does not have a redact mode for request bodies.

#### Add or refine a pattern

1. Edit `scripts/dlp_patterns.py`.
2. Test the pattern locally:

   ```sh
   python3 - <<'PY'
   import sys
   sys.path.insert(0, "scripts")
   from dlp_patterns import scan_text
   print(scan_text("my test value"))
   PY
   ```

3. Add a canary case to `docker/prompt-dlp/leak_test.py` and/or
   `docker/egress-broker/leak_test.py`.
4. `./bin/build` (the pattern file is baked into the images).
5. `./bin/reload`.
6. `./bin/verify`.

Avoid patterns with catastrophic backtracking or broad matches that block
normal source code. Prefer anchored, format-specific rules. The generic
credential-assignment rule is intentionally broad; it will flag things like
`password = "correcthorsebatterystaple"` in tests. Use placeholders in fixtures
or refine the rule rather than disabling the scanner.

#### Testing prompt DLP

From an authenticated shell inside a run, or with `bin/agent --run` and a
temporary test, send:

```sh
TOKEN="$(cat /run/secrets/gateway_token)"
curl -sS -o /tmp/dlp.out -w '%{http_code}\n' \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"model":"deepseek-v4-flash","messages":[{"role":"user","content":"CANARY_PROMPT_DLP_1234567890"}]}' \
  http://llm-gateway:24080/v1/chat/completions
cat /tmp/dlp.out
```

Expected: `403` and a `dlp_block` error; `prompt-dlp` logs only the rule names.
A clean request proceeds to LiteLLM and may fail there for model/key reasons,
which is not a DLP failure.

### 5.8 OpenCode policies and permissions

`config/opencode/base.json` is rendered into
`.agent/generated/opencode.json` and mounted read-only at
`/etc/opencode/opencode.json`.

Key settings:

- `default_agent: build` — default agent.
- `update: disable` — OpenCode cannot self-update in the sandbox.
- `snapshots: false` — OpenCode does not perform Git snapshot writes.
- `formatter: false` — no automatic formatter execution.
- `instructions: ["/etc/opencode/AGENTS.md"]` — global rules.
- `providers.litellm` — the only provider; gateway URL and scoped token.
- `policies` — deny all providers, then allow `litellm`; deny MCP, plugins,
  skills, webfetch, websearch, and external directories.
- `permissions` — deny reads of environment/credential/key files; deny edits to
  `.git`, `.opencode`, OpenCode config, `AGENTS.md`, and CI files.

These are defense-in-depth and policy controls, not the only boundary. The
filesystem mounts and network rules are separate.

If you need a capability:

- **A tool** (for example webfetch): add a policy allow after understanding that
  it becomes an egress channel. Prefer the broker.
- **An MCP server or plugin**: the design intentionally denies them. Enabling
  one requires reviewing its code, network access, and data access; do not add
  a permissive `*` policy.
- **A read exception**: add a narrowly scoped permission; remember the file may
  still be absent from the snapshot.
- **Project-specific instructions**: edit `config/opencode/AGENTS.md` on the
  host. It is mounted read-only. Changes apply on the next run. Do not rely on a
  project `AGENTS.md` surviving the export gate.
- **A different default agent**: edit `default_agent`, but review what that
  agent can do. Agents do not bypass the policies.

Changes to `base.json` or `AGENTS.md` apply at the next `bin/agent` render; no
image rebuild is needed. Generated `opencode.json` must not be edited directly.

### 5.9 Git protections

`config/git/gitconfig` is mounted read-only at `/etc/git/gitconfig` and exported
via `GIT_CONFIG_GLOBAL`. It sets:

- `core.hooksPath = /etc/git/empty-hooks` — hooks are never loaded from the
  repository.
- `core.fsmonitor = false` — no filesystem monitor execution.
- `core.pager = cat`, `core.editor = true` — non-interactive.
- `core.sshCommand = /bin/false` — no SSH.
- `credential.helper =` — no host credential helper.
- `protocol.ext.allow = never` — no ext transport.
- `transfer/fetch/receive.fsckObjects = true` — stricter object checks.
- `safe.directory = /workspace` — avoids dubious-ownership failures with the
  host UID/GID.

The sandbox also sets `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL`, and a
`GIT_CONFIG_COUNT` override for `core.hooksPath` and `core.fsmonitor`, so even a
writable `.git/config` cannot re-enable hooks. `GIT_TERMINAL_PROMPT=0` and
`GIT_ASKPASS=/bin/false` prevent interactive credential prompts.

`direct` mode mounts `.git` read-only. `direct-commit` leaves objects, refs, and
the index writable but mounts hooks/info/modules/config read-only when present.
The hook canary in `bin/verify` proves hooks do not execute. Do not disable the
canary or remove the empty hooks path.

Host-side snapshot, export, and audit commands also run Git with a hardened
environment: no system/global config, hooks disabled, fsmonitor disabled, pager
and editor forced to non-executables, and Git command-line overrides for the
unsafe settings. Before export, the snapshot's agent-writable `.git` metadata is
replaced with a minimal safe config and hook/attribute/alternate paths are
removed. This prevents a malicious repository from defining a `filter`, external
diff, or fsmonitor command that executes on the host during export or audit.

If you must allow another safe directory, add it to `safe.directory`; do not
disable the ownership check globally. If you need SSH access, that is an egress
and credential decision; the current design intentionally disables it.

### 5.10 Network layout and firewall

Fixed layout:

| Address | Service |
|---|---|
| `172.31.240.1` | Docker bridge gateway (blocked by firewall) |
| `172.31.240.2` | `llm-gateway` |
| `172.31.240.3` | `sandbox-netns` / sandbox |
| `172.31.240.4` | `sandbox-egress` (allowlist mode) |
| `172.31.240.5` | `egress-broker` (broker mode) |

The sandbox shares `sandbox-netns` and is never given `NET_ADMIN`. A one-shot
`sandbox-firewall` container with `NET_ADMIN` applies:

- default DROP on INPUT/FORWARD/OUTPUT;
- an explicit DROP for Docker's embedded DNS at `127.0.0.11` (UDP and TCP);
- loopback (excluding the embedded DNS destination above);
- established/related traffic;
- gateway TCP 24080;
- egress proxy TCP 24128 when allowlist mode is selected;
- broker TCP 24443 when broker mode is selected.

The rules persist in the shared netns after the firewall container exits. The
sandbox has no default route and no working resolver. `public_net` also disables
Docker inter-container communication, so the egress proxies and broker cannot
pivot through each other.

If you need a different subnet:

1. Change `networks.sandbox_net.ipam` in `compose.yaml`.
2. Change every `ipv4_address`, the `sandbox-firewall` environment IPs, and the
   generated `/etc/hosts` entries in `bin/agent`.
3. Update `docker/agent/verify-security.sh` (host bridge probe) and
   `bin/verify` (host-to-sandbox probe).
4. Update this guide and any tests.
5. `./bin/down`, then rebuild/restart. Existing networks keep the old subnet
   until removed.

This is deliberately tedious; fixed addresses make the firewall simple and
auditable. Do not run two stacks with the same subnet.

`SANDBOX_FIREWALL=off` requires `--unsafe-no-firewall`; the wrapper fails closed
otherwise. With the firewall off you still have Docker internal networks and no
published ports, but you lose the explicit default-DROP, the embedded-DNS
block, and host-to-sandbox protection. Treat it as a temporary debugging
posture, not a default.

`SANDBOX_RUNTIME=runsc` uses gVisor if Docker has the runtime configured.
`bin/preflight` checks it. On macOS/Docker Desktop, `runsc` is generally not
available; use a Linux host or a dedicated VM. A dedicated VM remains the
strongest practical isolation.

### 5.11 Secrets lifecycle

| Secret | Consumers | Mounted at | Purpose |
|---|---|---|---|
| `GATEWAY_TOKEN` | sandbox, `llm-gateway` | `/run/secrets/gateway_token` | Authenticates sandbox → gateway; the sandbox gets only this scoped token. |
| `LITELLM_MASTER_KEY` | `llm-gateway`, `llm-proxy` | `/run/secrets/litellm_master_key` | Caddy replaces the sandbox token with this upstream key; LiteLLM master key. |
| `DEEPSEEK_API_KEY` | `llm-proxy` | `/run/secrets/deepseek_api_key` | DeepSeek provider credential. |
| `ANTHROPIC_API_KEY` | `llm-proxy` | `/run/secrets/anthropic_api_key` | Anthropic provider credential. |
| `OPENAI_API_KEY` | `llm-proxy` | `/run/secrets/openai_api_key` | OpenAI provider credential. |
| `broker/GITHUB_TOKEN` | `egress-broker` | `/run/secrets/github_token` | Injected into approved GitHub API requests. |

The sandbox sees only `gateway_token`. It does not see the master key or any
provider key, and `bin/verify` asserts this.

Commands:

```sh
./bin/secrets init
./bin/secrets set DEEPSEEK_API_KEY
./bin/secrets list
./bin/secrets rotate GATEWAY_TOKEN
./bin/secrets rotate LITELLM_MASTER_KEY
```

After rotation:

- `GATEWAY_TOKEN`: recreate `llm-gateway`; existing sandboxes have the old token
  and will fail until restarted.
- `LITELLM_MASTER_KEY`: recreate `llm-gateway` and `llm-proxy`.
- Provider key: recreate `llm-proxy`.
- Broker credential: recreate `egress-broker`.

If a key may have leaked into a run:

1. Rotate it at the provider and locally.
2. Remove the run directory or at least its `home` and exported patch.
3. Check `bin/logs` and the provider's audit logs for use.
4. Review `prompt-dlp`, broker, and Squid logs for the rule/host, not the secret.
5. Re-run `bin/verify`.

Never commit `secrets/`. `.gitignore` excludes it, but verify before pushing.

### 5.12 Resource limits and performance

`compose.yaml` sets:

- `sandbox`: `mem_limit: 4g`, `cpus: 2`, `pids_limit: 1024`, 512 MB `/tmp`.
- `llm-proxy`: `mem_limit: 2g`, `cpus: 2`, `pids_limit: 512`, 512 MB `/tmp`.
- Gateway, DLP, egress proxies, and broker: 256–512 MB and 256 PIDs.
- 10 MB × 3 log files per service.

Increase limits if large builds or long contexts fail; decrease them if you want
a smaller blast radius. Do not give the sandbox `privileged` or additional
capabilities to “make it work.” Fix the actual resource limit.

LiteLLM starts with one worker (`--num_workers 1`). More workers can help
throughput but increase memory and duplicate caches. The proxy is shared by
runs; a model config change requires a restart/reload.

The sandbox `/tmp` is tmpfs; large builds can fill it. Use the project workspace
for artifacts, and clean up. `STATE_MODE=project` keeps session data and can grow
over time.

---

## 6. Verification

### 6.1 The built-in suite

```sh
./bin/preflight          # host prerequisites
./bin/build              # image build
./bin/verify --no-start  # static/Compose posture only
./bin/verify             # starts services and runs runtime assertions
```

`bin/verify` uses the latest run by default; select one:

```sh
./bin/verify --run <run-id>
```

It checks:

- Compose config: read-only root, cap-drop, no-new-privileges, non-root, no
  published ports, no Docker socket, no host credential mounts, internal
  networks, only the gateway secret in the sandbox, no provider keys in the
  sandbox.
- Host secret scanner blocks an AWS-looking key.
- Export gate blocks a changed CI workflow.
- Runtime: no default route, DNS blocked, public IP/metadata/host bridge
  blocked, gateway reachable, LiteLLM not directly reachable, selected egress
  proxy/broker state.
- Sandbox security script: capabilities, no-new-privileges, read-only root,
  Git protections, hook canary, secret mounts, live `.env`, mount denial,
  setuid inventory.
- Prompt DLP canary.
- Broker DLP/validation tests in broker mode.
- Host cannot initiate a connection into the sandbox.

`bin/verify` does not make a real model request and does not test every domain
in your allowlist. Do those tests separately when you change those areas.

### 6.2 Manual checks inside the sandbox

```sh
./bin/shell
```

Then:

```sh
id
ip route
cat /etc/resolv.conf
getent hosts llm-gateway
nslookup example.com 127.0.0.11   # must fail: Docker embedded DNS is dropped
nc -z -w 2 127.0.0.11 53          # must fail: TCP DNS is dropped

# Direct egress should fail
curl --noproxy '*' --connect-timeout 3 -sS -o /dev/null https://1.1.1.1
curl --noproxy '*' --connect-timeout 3 -sS -o /dev/null http://169.254.169.254/

# Gateway health (no auth)
curl --noproxy '*' -sS http://llm-gateway:24080/health

# Gateway models (scoped token)
TOKEN="$(cat /run/secrets/gateway_token)"
curl --noproxy '*' -sS -H "Authorization: Bearer $TOKEN" \
  http://llm-gateway:24080/v1/models

# Provider keys must not be present
env | grep -E 'DEEPSEEK_API_KEY|ANTHROPIC_API_KEY|OPENAI_API_KEY|LITELLM_MASTER_KEY' || true
```

Remember that `bin/shell` bypasses the normal entrypoint, so it does not export
`LITELLM_GATEWAY_KEY`; read the gateway token file as above.

### 6.3 Test a model change

```sh
./bin/models
./bin/reload
./bin/agent --model <alias> --run "Reply with OK"
```

If it fails:

- `bin/logs llm-proxy` — did LiteLLM load the alias?
- `bin/logs prompt-dlp` — was it blocked?
- `bin/logs llm-egress` — was the provider domain allowed?
- Check the key file and the provider account.

### 6.4 Test an egress change

Use the allowlist test in section 5.4. For the broker, configure a harmless
host and use `GET` with no body, then approve. For a new credential, verify the
upstream response, not just the approval log.

### 6.5 Test the firewall itself

`bin/verify` covers the important cases. If you change the subnet or firewall
script, also run the host-to-sandbox listener test manually or inspect the
`bin/verify` failure. Do not rely on Docker's `internal: true` alone; the
explicit firewall is the part that blocks host-initiated connections.

---

## 7. Recipes

### 7.1 Start work on a new project

```sh
PROJECT_DIR=/path/to/repo ./bin/agent --profile edit
```

Or set it in `config/agent.env` and run `./bin/agent`.

### 7.2 Add a model alias for an existing provider

1. Edit `config/models.json`.
2. `./bin/models`.
3. `./bin/reload`.
4. `./bin/agent --model <alias>`.

### 7.3 Add a new OpenAI-compatible provider

Follow section 5.6, including the entrypoint/secret wiring and the provider
allow/deny lists. This is the most error-prone tuning path; verify each layer:

- `bin/models` shows the alias.
- `bin/logs llm-proxy` shows the provider request.
- `bin/logs llm-egress` shows the allowed domain.
- A real request succeeds.

### 7.4 Allow npm and PyPI for one run

```sh
./bin/agent --profile install \
  --allow registry.npmjs.org,pypi.org,files.pythonhosted.org
```

Do not add these to the default deny profile unless you need them routinely.

### 7.5 Approve a GitHub API call

1. Configure `api.github.com` and the `github_token` secret (section 5.5).
2. `./bin/reload`.
3. `./bin/agent --profile api`.
4. Send the request from the sandbox.
5. On the host, `./bin/egress-pending`, inspect, `./bin/egress-approve <id>`.

### 7.6 Run a local model

```sh
./bin/ollama pull qwen3-coder
./bin/ollama list
./bin/agent --profile local
```

If the alias name differs, update `config/models.json`, `./bin/models`,
`./bin/reload`.

### 7.7 Recover from a blocked export

1. Read `export/report.json`.
2. If a blocked path is legitimate but should not be exported, change the policy
   in `scripts/export_patch.py` only after understanding the risk.
3. If a secret was found, remove the value from the snapshot change and rotate
   it if it was real.
4. If only a risky path is flagged, review the patch and use
   `--allow-risky`.
5. If the host tree is dirty, commit/stash it or use `--force` consciously.
6. Re-run `./bin/export`.

### 7.8 Rotate keys after a suspected leak

```sh
./bin/secrets rotate DEEPSEEK_API_KEY
./bin/reload
```

Then revoke the old key at the provider, inspect logs, delete the affected run,
and re-run `./bin/verify`. Rotating the gateway/master keys requires recreating
the gateway and proxy as described in section 5.11.

### 7.9 Add a snapshot exclusion

Add the name/pattern to `scripts/snapshot.py`, then start a new run. Do not edit
a completed snapshot to hide a problem; the report is evidence.

### 7.10 Enable gVisor on Linux

1. Install/configure `runsc` for Docker and confirm it appears in
   `docker info` runtimes.
2. Set `SANDBOX_RUNTIME=runsc` in `config/agent.env`.
3. `./bin/preflight` must pass the runtime check.
4. Start a run and `./bin/verify`.

If `preflight` fails, do not silently switch back to `runc` for sensitive work;
fix the runtime or accept the weaker posture explicitly.

---

## 8. Troubleshooting

### 8.1 Startup and preflight

**`PROJECT_DIR is not set`**
: Set it in `config/agent.env` or pass `--project`.

**`preflight failed`**
: Read the specific `FAIL`. Common causes: Docker daemon down, state directory
  not writable, Docker Desktop file sharing not enabled for `STATE_DIR`,
  iptables/conntrack unavailable, missing generated secrets, no provider key,
  or `runsc` not configured.

**`docker compose complains about SANDBOX_HOME_DIR`**
: Use `bin/agent`, `bin/verify`, `bin/reload`, or `bin/ollama`. They set the
  variable. If calling Compose manually, export it yourself.

**`gateway` exits with code 126**
: The stock Caddy binary has `cap_net_bind_service`; `no-new-privileges` makes
  exec fail. Rebuild the gateway image (the Dockerfile removes the capability
  with `setcap -r`).

**Containers cannot start because of a network/subnet conflict**
: `./bin/down`, remove stale networks if necessary, or change the stack subnet
  as described in section 5.10. Do not run two instances with the same fixed
  subnet.

### 8.2 Sandbox and workspace

**`git status` fails in direct mode with “dubious ownership”**
: The wrapper mounts `config/git/gitconfig` with `safe.directory=/workspace`.
  Use the wrapper; do not run Compose manually with a different `GIT_CONFIG_GLOBAL`.

**`direct` mode fails because the project is not a Git repository**
: Expected. Use snapshot mode, or initialize Git.

**`direct-commit` fails for a worktree**
: It requires a normal `.git` directory. Use snapshot for worktrees.

**A protected file/directory appears after a direct run**
: Direct mode only mounts protected paths that already existed at start; it
  deliberately does not create shadow files in your repo. The post-run audit
  flags new high-risk paths. This is a residual TOCTOU risk of direct mode; use
  snapshot for untrusted code.

**Snapshot aborted with secret findings**
: Remove or rotate the secret, or replace fixtures with obvious placeholders.
  Do not add a real secret to `ALLOWED_ENV_TEMPLATES`.

**Snapshot omitted a file you expected**
: Check `snapshot.json` → `skipped_files`, `.gitignore` for Git sources, and the
  exclusion lists. The snapshot is intentionally conservative.

### 8.3 Export and audit

**`export is only available for snapshot runs`**
: Use `bin/audit` for direct modes. Snapshot mode is required for patch export.

**Export blocked by a CI workflow / `.opencode` / `.env`**
: These paths are intentionally non-exportable. Move the change out of the
  agent, or change the policy only with a deliberate review.

**Export requires `--allow-risky`**
: Review the flagged script/Dockerfile/package file, then pass the flag. Do not
  add the flag to a wrapper default.

**Patch does not apply cleanly**
: The host moved since the snapshot. Rebase/merge manually or re-run on a fresh
  snapshot. `--force` only bypasses the clean-tree check, not patch conflicts.

**Project is not a Git repository**
: `bin/export --apply` needs Git. Initialize the target or apply the patch
  manually after review.

### 8.4 Network and egress

**No DNS inside the sandbox**
: Intentional. Use the gateway or the selected egress proxy; do not add a
  resolver.

**`curl` direct to the internet fails**
: Expected in all modes. Use the gateway for models and the allowlist proxy or
  broker for APIs.

**Allowlisted domain is denied**
: Check exact spelling, leading dot, that the domain is not under
  `provider-deny.txt`, that you used `--egress allowlist` (not deny), and that
  the run was started after the allowlist was written. Squid logs show the
  denied host.

**Squid fails with “Bungled ... acl allowed_domains”**
: The allowlist contains a domain and its subdomain, or an invalid entry.
  Remove the duplicate/overlap or use a broader leading-dot entry. Provider
  lists are raw Squid files and are not normalized for you.

**Provider request blocked by egress**
: Add the API domain to `config/egress/provider-allow.txt`, ensure the model's
  upstream uses HTTPS, then `bin/reload` and check `llm-egress` logs.

**Provider request hits DLP**
: Check `prompt-dlp` logs for rule names. Remove the sensitive content or tune
  the pattern; do not disable DLP to “make the model work.”

### 8.5 Broker

**`bin/egress` says the latest run does not use the broker**
: Start `./bin/agent --profile api`. The helper only addresses the latest
  broker run.

**Request times out with 408**
: No approval within `approval_timeout_seconds`. Run `bin/egress-pending` and
  approve/deny promptly, or increase the timeout for a legitimate slow review.

**403 “target host is not in approvable_domains”**
: Add the exact host or a leading-dot suffix to `config/broker/config.json`;
  recreate the broker.

**403 “Blocked by egress DLP”**
: The request body/URL/headers contain a secret pattern. Remove it; the broker
  does not redact request bodies.

**403 private/non-public address**
: The target resolves to a private, loopback, link-local, or reserved address.
  This is intentional. Do not add a private-IP escape hatch unless you have
  redesigned the threat model.

**Credential not injected**
: Check `secret_file` path inside the broker, that the Docker secret is mounted
  under that target, that the file is non-empty, and that the host matches the
  credential key. Recreate the broker after changes.

**Custom header missing**
: Add it to `allowed_request_headers`; all non-allowlisted headers are stripped
  by design.

### 8.6 Models and local mode

**Model alias missing**
: The secret file is missing/empty, or the alias was not rendered. Run
  `./bin/models`, check `available.json`, then `./bin/reload`.

**Authentication error from the provider**
: The key is wrong/revoked, or you are still using a test key. Rotate/set the
  key and recreate `llm-proxy`.

**Local model fails**
: `./bin/ollama pull <model>` first; confirm the exact model name and update
  `config/models.json` if needed. Check the Ollama service logs and that
  `inference_net` is up. The sandbox cannot reach Ollama directly by design.

**LiteLLM has the old model list after editing**
: It loaded the config at startup. `./bin/models && ./bin/reload`, or start a
  new run.

### 8.7 Verification and cleanup

**`bin/verify` says no run found**
: Start a run first; verification is tied to a run's manifest and workspace
  override.

**`bin/verify` fails because the workspace override is missing**
: The run directory was cleaned or moved. Start a new run.

**Out of disk**
: `bin/clean --all`, `docker system df`, remove unused images/volumes
  consciously. Do not delete `secrets/` unless you intend to rotate everything.

---

## 9. Security review checklist

Before using the stack for real code:

- [ ] `PROJECT_DIR` points to the intended repository.
- [ ] `WORKSPACE_MODE=snapshot` unless you have documented why direct mode is
      necessary.
- [ ] `SANDBOX_EGRESS=deny` unless a specific package/API workflow requires
      more.
- [ ] `bin/verify` passes; warnings are understood.
- [ ] The sandbox has only `gateway_token`; no provider or master key.
- [ ] The model provider exposure is acceptable; `confidential` is acknowledged
      if used.
- [ ] The broker `approvable_domains` is minimal; no broad `*` or auto-approve
      unless justified.
- [ ] `provider-allow.txt` contains only providers you use.
- [ ] DLP patterns were not weakened to silence a real finding.
- [ ] `secrets/` is not tracked by Git and has mode `0700/0600`.

Before applying an export:

- [ ] Read `report.json` and `changes.patch`.
- [ ] No blocked paths, secrets, or unsafe symlinks.
- [ ] Risky files were reviewed and `--allow-risky` is intentional.
- [ ] The host tree is clean or `--force` is intentional.
- [ ] You will review/test the applied change before running it on the host.

Before changing security configuration:

- [ ] Understand which layer the change affects (workspace, network, DLP,
      provider, Git, secrets).
- [ ] Make the smallest change.
- [ ] Update tests or add a canary.
- [ ] Run `bin/preflight`, `bin/verify`, and a real request.
- [ ] Record why in the commit message or an ADR.

---

## 10. Command reference

### The Unified `paladin` CLI

The `paladin` executable provides a convenient frontend to all operations and can be executed from any project directory on your system:

| Command | Underlying Script | Purpose |
|---|---|---|
| `paladin [run]` | `bin/agent` | Start secured agent session for current project |
| `paladin shell` | `bin/shell` | Launch interactive bash shell in sandbox |
| `paladin init` | `bin/secrets init` | Generate internal gateway & proxy master keys |
| `paladin secrets [set/list]` | `bin/secrets` | Inspect or configure provider API credentials |
| `paladin preflight` | `bin/preflight` | Audit host system & Docker isolation capabilities |
| `paladin build` | `bin/build` | Build all local container images |
| `paladin verify` | `bin/verify` | Execute full automated security test suite |
| `paladin export [--apply]` | `bin/export` | Review or apply cleansed snapshot patch |
| `paladin audit` | `bin/audit` | Audit direct-mount project modifications |
| `paladin scan [PATH]` | `bin/scan` | Scan project files for secret patterns |
| `paladin models` | `bin/models` | Render model configs and check availability |
| `paladin reload` | `bin/reload` | Recreate proxy services after config changes |
| `paladin pending` | `bin/egress-pending` | List API egress requests awaiting approval |
| `paladin approve <id>` | `bin/egress-approve` | Authorize a queued broker request |
| `paladin deny <id>` | `bin/egress-deny` | Reject a queued broker request |
| `paladin down [--volumes]` | `bin/down` | Stop active container services |
| `paladin logs [SERVICE]` | `bin/logs` | Stream live container logs |
| `paladin clean` | `bin/clean` | Remove old run directories |
| `paladin install-cli` | — | Symlink `paladin` to `~/.local/bin` for global access |

### Session Flags (`paladin` / `bin/agent`)

```text
--profile edit|install|api|confidential|local
--workspace snapshot|direct|direct-commit
--egress deny|allowlist|broker
--allow DOMAIN[,DOMAIN...]       allowlist mode only; replaces config list
--model ALIAS
--project PATH
--run, -r MESSAGE                one-shot OpenCode run
--shell                          bash in sandbox (not with --run)
--ack-external-model             confidential profile acknowledgement
--allow-secrets                  show credential files read-only in direct mode
--unsafe-no-firewall             required if firewall is off
--no-preflight
--build
--dry-run                        prepare snapshot/manifest, do not start
-- EXTRA...                      pass through to opencode run
```

### Other commands

| Command | Purpose |
|---|---|
| `bin/preflight` | Host/Docker prerequisites and firewall probe |
| `bin/build` | Build all images |
| `bin/reload` | Recreate proxy services after config changes |
| `bin/models` | Render LiteLLM/OpenCode config and list availability |
| `bin/shell` | Bash in a sandbox run |
| `bin/verify [--run ID] [--no-start]` | Security verification |
| `bin/export [--run ID] [--apply] [--allow-risky] [--force]` | Snapshot patch export |
| `bin/audit [--project PATH] [--json]` | Direct-mode change audit |
| `bin/scan [PATH] [--git-only] [--include-entropy] [--json]` | Host secret scan |
| `bin/secrets init|set NAME|rotate NAME|list` | Secret lifecycle |
| `bin/egress-pending` | List broker approvals |
| `bin/egress-approve ID` | Approve one broker request |
| `bin/egress-deny ID` | Deny one broker request |
| `bin/egress list|approve ID|deny ID|health` | Broker admin |
| `bin/ollama [list|pull MODEL|...]` | Manage local Ollama |
| `bin/down [--volumes]` | Stop containers/networks |
| `bin/logs [SERVICE...]` | Follow logs |
| `bin/clean [--keep N] [--all]` | Delete old run directories |
| `make compile` | Byte-compile host/container Python |

Useful `docker` diagnostics (read-only):

```sh
docker ps --filter name=agent-paladin --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
docker logs --tail 100 agent-paladin-llm-proxy-1
docker network inspect agent-paladin_sandbox_net
docker stats --no-stream
```

Do not add a `ports:` entry to the sandbox or proxy services; the design has no
published host ports.

---

## 11. Known limitations

- **External model providers see prompts and code.** Snapshot, DLP, and egress
  controls reduce accidental exposure but cannot un-send data to a provider.
- **DLP is regex-based.** It catches known formats and accidental assignments;
  it does not stop encoding, splitting, or bespoke exfiltration.
- **Allowlist egress is domain-level.** No TLS interception means no path,
  method, or response-content control. Use the broker for schema-level/API
  control, and still review what you approve.
- **The broker trusts its own code and config.** It holds external credentials;
  a broker compromise is a credential compromise.
- **Docker shares the host kernel.** Rootless Docker/userns/gVisor/dedicated VM
  are the mitigations; the stack cannot provide kernel isolation by itself.
- **Direct modes are reduced assurance.** They expose host files immediately;
  the audit is after the fact. Snapshot mode is the default for a reason.
- **No artifact proxy or package-integrity system.** The allowlist controls
  domains, not package contents. Use lockfiles, signatures, and script-disabled
  installs.
- **No out-of-band secret manager.** Secrets are local files with Docker secret
  mounts. Protect the host and `secrets/` directory.
- **macOS Docker Desktop uses a shared VM.** Use a dedicated VM or Linux host
  for a stronger boundary.
- **Human approval is only as good as the reviewer.** Read the pending request;
  do not approve blindly.

---

## 12. License and third-party components

The source code, configuration, and documentation in this repository are
licensed under the Apache License 2.0. The license does not cover third-party
software pulled or installed at build/run time, model weights, provider APIs,
trademarks, or logos.

- See [`LICENSE`](../LICENSE) for the license text.
- See [`NOTICE`](../NOTICE) for the copyright notice, and third-party trademark
  notice.
- See [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md) for the container
  images, packages, model providers, and assets used by the project.

Operational implications:

- **You supply the provider keys.** The project does not include API keys or
  model weights.
- **You are responsible for data flows.** Prompts and code go to the provider
  you configure. Do not use the stack with data you are not authorized to send
  to that provider.
- **Built images contain third-party software.** The egress images include
  Squid (GPL-2.0), and the sandbox image includes Git and Bash from Alpine.
  Publishing built images triggers those licenses' notice and source-offer
  obligations. The source-only release does not publish images.
- **Security is not guaranteed.** Use the known-limitations section above and
  the disclaimer in `README.md` when deciding whether the isolation is
  sufficient for your environment.

The repository is not legal advice. Review the licenses and provider terms
with qualified counsel before commercial or regulated use.

---

For the threat model, architecture diagram, and a shorter quick start, see
[`README.md`](../README.md).
