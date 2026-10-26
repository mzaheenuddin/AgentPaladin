#!/bin/bash
set -u

FAIL=0

pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; FAIL=1; }
warn() { printf 'WARN  %s\n' "$*"; }
skip() { printf 'SKIP  %s\n' "$*"; }

expect_ok() {
  local description="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    pass "$description"
  else
    fail "$description"
  fi
}

expect_fail() {
  local description="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    fail "$description"
  else
    pass "$description"
  fi
}

MODE="${SANDBOX_WORKSPACE_MODE:-unknown}"
EGRESS_MODE="${SANDBOX_EGRESS_MODE:-deny}"

if [[ -z "${LITELLM_GATEWAY_KEY:-}" && -f /run/secrets/gateway_token ]]; then
  LITELLM_GATEWAY_KEY="$(cat /run/secrets/gateway_token)"
  export LITELLM_GATEWAY_KEY
fi

export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/etc/git/gitconfig
export GIT_CONFIG_COUNT=2
export GIT_CONFIG_KEY_0=core.hooksPath
export GIT_CONFIG_VALUE_0=/etc/git/empty-hooks
export GIT_CONFIG_KEY_1=core.fsmonitor
export GIT_CONFIG_VALUE_1=false

printf '== sandbox security verification ==\n'
printf 'workspace mode: %s\n' "$MODE"
printf 'egress mode:    %s\n' "$EGRESS_MODE"
printf 'uid:            %s\n' "$(id -u)"
printf 'gid:            %s\n\n' "$(id -g)"

if [[ "$(id -u)" -ne 0 ]]; then
  pass "runs as a non-root user"
else
  fail "runs as root"
fi

CAP_EFF="$(awk '$1 == "CapEff:" { print $2 }' /proc/self/status 2>/dev/null || true)"
if [[ -n "$CAP_EFF" && "$CAP_EFF" =~ ^0+$ ]]; then
  pass "effective capabilities are empty (CapEff=$CAP_EFF)"
else
  fail "effective capabilities are not empty (CapEff=${CAP_EFF:-unknown})"
fi

NO_NEW_PRIVS="$(awk '$1 == "NoNewPrivs:" { print $2 }' /proc/self/status 2>/dev/null || true)"
if [[ "$NO_NEW_PRIVS" == "1" ]]; then
  pass "no-new-privileges is active"
else
  fail "no-new-privileges is not active (NoNewPrivs=${NO_NEW_PRIVS:-unknown})"
fi

ROOT_OPTS="$(findmnt -no OPTIONS / 2>/dev/null || true)"
case ",${ROOT_OPTS}," in
  *,ro,*) pass "root filesystem is read-only" ;;
  *) fail "root filesystem is not read-only (options: ${ROOT_OPTS:-unknown})" ;;
esac

if [[ -S /var/run/docker.sock || -S /run/docker.sock ]]; then
  fail "a Docker socket is present"
else
  pass "no Docker socket is present"
fi

if ip -4 route 2>/dev/null | grep -q '^default '; then
  fail "a default route exists"
else
  pass "no default route exists"
fi

if timeout 4 nslookup example.com >/dev/null 2>&1; then
  fail "DNS resolution succeeds"
else
  pass "DNS resolution is blocked"
fi

# Docker's embedded resolver is reachable on loopback unless the firewall
# drops it explicitly. Test both UDP (nslookup) and TCP DNS.
if timeout 4 nslookup example.com 127.0.0.11 >/dev/null 2>&1; then
  fail "Docker embedded DNS resolver (127.0.0.11) is reachable"
else
  pass "Docker embedded DNS resolver (127.0.0.11) is blocked"
fi

if nc -z -w 2 127.0.0.11 53 >/dev/null 2>&1; then
  fail "Docker embedded DNS TCP port is reachable"
else
  pass "Docker embedded DNS TCP port is blocked"
fi

if curl --noproxy '*' --connect-timeout 3 --max-time 5 -fsS -o /dev/null https://1.1.1.1 2>/dev/null; then
  fail "direct HTTPS to a public IP succeeds"
else
  pass "direct HTTPS to a public IP fails"
fi

if curl --noproxy '*' --connect-timeout 3 --max-time 5 -fsS -o /dev/null http://169.254.169.254/ 2>/dev/null; then
  fail "cloud metadata endpoint is reachable"
else
  pass "cloud metadata endpoint is blocked"
fi

if curl --noproxy '*' --connect-timeout 3 --max-time 5 -fsS -o /dev/null http://172.31.240.1/ 2>/dev/null; then
  fail "host bridge gateway is reachable"
else
  pass "host bridge gateway is blocked"
fi

expect_ok "gateway health endpoint is reachable" \
  curl --noproxy '*' --max-time 10 -fsS -o /dev/null http://llm-gateway:24080/health

if [[ -n "${LITELLM_GATEWAY_KEY:-}" ]]; then
  expect_ok "authenticated gateway model list is reachable" \
    curl --noproxy '*' --max-time 20 -fsS -o /dev/null \
      -H "Authorization: Bearer ${LITELLM_GATEWAY_KEY}" \
      http://llm-gateway:24080/v1/models
else
  fail "LITELLM_GATEWAY_KEY is not set"
fi

if curl --noproxy '*' --connect-timeout 2 --max-time 3 -fsS -o /dev/null http://llm-proxy:24000/ 2>/dev/null; then
  fail "LiteLLM is directly reachable from the sandbox"
else
  pass "LiteLLM is not directly reachable from the sandbox"
fi

if [[ "$EGRESS_MODE" == "allowlist" ]]; then
  expect_ok "sandbox egress proxy is reachable" \
    nc -z -w 3 sandbox-egress 24128
elif [[ "$EGRESS_MODE" == "broker" ]]; then
  expect_ok "egress broker health endpoint is reachable" \
    curl --noproxy '*' --max-time 5 -fsS -o /dev/null http://egress-broker:24443/health
  if curl --noproxy '*' --connect-timeout 2 --max-time 3 -fsS -o /dev/null http://sandbox-egress:24128/ 2>/dev/null; then
    fail "generic egress proxy is reachable in broker mode"
  else
    pass "generic egress proxy is blocked in broker mode"
  fi
else
  if nc -z -w 3 sandbox-egress 24128 >/dev/null 2>&1; then
    fail "a generic egress proxy is reachable in deny mode"
  else
    pass "no generic egress proxy is reachable"
  fi
fi

expect_fail "root filesystem write is denied" touch /etc/.agent-paladin-verify
expect_fail "OpenCode config write is denied" touch /etc/opencode/.agent-paladin-verify

if [[ -e /workspace/.git ]]; then
  case "$MODE" in
    direct)
      expect_fail "host .git is read-only in direct mode" touch /workspace/.git/.agent-paladin-verify
      ;;
    direct-commit)
      expect_fail "host .git/hooks is read-only in direct-commit mode" touch /workspace/.git/hooks/.agent-paladin-verify
      expect_fail "host .git/config is read-only in direct-commit mode" touch /workspace/.git/config
      ;;
    snapshot)
      pass "snapshot uses a sandbox-local .git (host .git is not mounted)"
      ;;
    *)
      warn "unknown workspace mode; checking only generic write protections"
      ;;
  esac

  if git -C /workspace status --short >/dev/null 2>&1; then
    pass "git status works with the configured Git protections"
  else
    fail "git status fails inside the sandbox"
  fi
else
  skip "no /workspace/.git present"
fi

# A hook canary proves that the core.hooksPath override, not just file
# permissions, prevents hook execution. This runs entirely inside the sandbox.
HOOK_DIR="$(mktemp -d /tmp/agent-paladin-hook.XXXXXX)"
if git init -q "$HOOK_DIR" 2>/dev/null; then
  mkdir -p "$HOOK_DIR/.git/hooks"
  cat >"$HOOK_DIR/.git/hooks/pre-commit" <<'EOF'
#!/bin/sh
touch /tmp/agent-paladin-hook-fired
EOF
  chmod +x "$HOOK_DIR/.git/hooks/pre-commit"
  if git -C "$HOOK_DIR" \
      -c user.name="Agent Paladin Verify" \
      -c user.email="verify@localhost" \
      commit --allow-empty -m "hook canary" >/dev/null 2>&1; then
    if [[ -e /tmp/agent-paladin-hook-fired ]]; then
      fail "Git hook canary executed (hooks are not disabled)"
    else
      pass "Git hook canary did not execute"
    fi
  else
    fail "Git hook canary commit failed unexpectedly"
  fi
else
  warn "could not create a temporary Git repository for the hook canary"
fi
rm -rf "$HOOK_DIR" /tmp/agent-paladin-hook-fired

SECRET_NAMES="$(ls -1 /run/secrets 2>/dev/null || true)"
if [[ "$SECRET_NAMES" == "gateway_token" ]]; then
  pass "/run/secrets contains only the scoped gateway token"
else
  fail "unexpected secrets mounted in sandbox: ${SECRET_NAMES:-none}"
fi

if env | grep -Eq '^(DEEPSEEK_API_KEY|ANTHROPIC_API_KEY|OPENAI_API_KEY|LITELLM_MASTER_KEY)='; then
  fail "a provider or proxy master key is present in the sandbox environment"
else
  pass "no provider or proxy master key is present in the sandbox environment"
fi

if find /workspace -maxdepth 3 \( -name '.env' -o -name '.env.local' -o -name '.env.production' \) -print -quit 2>/dev/null | grep -q .; then
  if [[ "$MODE" == "snapshot" ]]; then
    fail "a live .env file is present in the snapshot workspace"
  else
    warn "a live .env file is present in the direct workspace; this is the reduced-assurance mode"
  fi
else
  pass "no live .env file is present in the workspace"
fi

mkdir -p /tmp/mnt
if mount -t tmpfs none /tmp/mnt >/dev/null 2>&1; then
  fail "mount succeeded"
  umount /tmp/mnt >/dev/null 2>&1 || true
else
  pass "mount is denied"
fi
rmdir /tmp/mnt >/dev/null 2>&1 || true

SETUID_FILES="$(find / -xdev -perm -4000 -type f 2>/dev/null | head -20)"
if [[ -z "$SETUID_FILES" ]]; then
  pass "no setuid binaries found"
else
  warn "setuid binaries present (no-new-privileges still applies):"
  printf '%s\n' "$SETUID_FILES" | sed 's/^/      /'
fi

printf '\n'
if [[ "$FAIL" -eq 0 ]]; then
  printf 'RESULT: PASS\n'
  exit 0
fi

printf 'RESULT: FAIL\n'
exit 1
