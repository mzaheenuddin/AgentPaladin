#!/bin/sh
set -eu

if [ -f /run/secrets/gateway_token ]; then
  GATEWAY_TOKEN="$(cat /run/secrets/gateway_token)"
  export GATEWAY_TOKEN
fi

if [ -f /run/secrets/litellm_master_key ]; then
  LITELLM_MASTER_KEY="$(cat /run/secrets/litellm_master_key)"
  export LITELLM_MASTER_KEY
fi

if [ -z "${GATEWAY_TOKEN:-}" ]; then
  echo "gateway: GATEWAY_TOKEN is empty" >&2
  exit 1
fi

if [ -z "${LITELLM_MASTER_KEY:-}" ]; then
  echo "gateway: LITELLM_MASTER_KEY is empty" >&2
  exit 1
fi

export XDG_DATA_HOME="${XDG_DATA_HOME:-/tmp/caddy/data}"
export XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-/tmp/caddy/config}"
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-/tmp/caddy/cache}"
mkdir -p "$XDG_DATA_HOME" "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME"

exec caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
