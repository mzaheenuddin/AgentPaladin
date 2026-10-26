#!/bin/bash
set -euo pipefail

export HOME="${HOME:-/home/agent}"
export XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
export XDG_DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
export XDG_STATE_HOME="${XDG_STATE_HOME:-$HOME/.local/state}"
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-$HOME/.cache}"

mkdir -p \
  "$XDG_CONFIG_HOME" \
  "$XDG_DATA_HOME/opencode" \
  "$XDG_STATE_HOME/opencode" \
  "$XDG_CACHE_HOME"

# Always replace the managed shell profile in HOME. A previous run (especially
# with STATE_MODE=project) must not be able to persist executable shell state.
rm -rf "$HOME/.bashrc"
cat <<'EOF' > "$HOME/.bashrc"
# AGENT_PALADIN_MANAGED
[ -z "$PS1" ] && return
shopt -s checkwinsize
PS1='agent-paladin:\w\$ '
EOF
chmod 0644 "$HOME/.bashrc"

if [[ -f /run/secrets/gateway_token ]]; then
  GATEWAY_TOKEN="$(cat /run/secrets/gateway_token)"
  if [[ -z "$GATEWAY_TOKEN" ]]; then
    echo "sandbox: gateway_token secret is empty" >&2
    exit 1
  fi
  export LITELLM_GATEWAY_KEY="$GATEWAY_TOKEN"
fi

export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/etc/git/gitconfig
export GIT_CONFIG_COUNT=2
export GIT_CONFIG_KEY_0=core.hooksPath
export GIT_CONFIG_VALUE_0=/etc/git/empty-hooks
export GIT_CONFIG_KEY_1=core.fsmonitor
export GIT_CONFIG_VALUE_1=false
export GIT_PAGER=cat
export PAGER=cat
export GIT_EDITOR=true
export GIT_TERMINAL_PROMPT=0
export GIT_ASKPASS=/bin/false
export GIT_AUTHOR_NAME="${GIT_AUTHOR_NAME:-Agent Paladin}"
export GIT_AUTHOR_EMAIL="${GIT_AUTHOR_EMAIL:-paladin@localhost}"
export GIT_COMMITTER_NAME="${GIT_COMMITTER_NAME:-Agent Paladin}"
export GIT_COMMITTER_EMAIL="${GIT_COMMITTER_EMAIL:-paladin@localhost}"

if [[ ! -f /etc/opencode/opencode.json ]]; then
  echo "sandbox: /etc/opencode/opencode.json is missing; run bin/agent" >&2
  exit 1
fi

if [[ "$#" -eq 0 ]]; then
  exec opencode --standalone
fi

if [[ "${1:-}" == "run" ]]; then
  shift
  exec opencode run --standalone "$@"
fi

case " $* " in
  *" --standalone "*) exec opencode "$@" ;;
  *) exec opencode --standalone "$@" ;;
esac
