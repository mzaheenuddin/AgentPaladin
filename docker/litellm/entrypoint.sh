#!/bin/sh
set -eu

if [ -f /run/secrets/litellm_master_key ]; then
  LITELLM_MASTER_KEY="$(cat /run/secrets/litellm_master_key)"
  export LITELLM_MASTER_KEY
fi

if [ -f /run/secrets/deepseek_api_key ]; then
  DEEPSEEK_API_KEY="$(cat /run/secrets/deepseek_api_key)"
  export DEEPSEEK_API_KEY
fi

if [ -f /run/secrets/anthropic_api_key ]; then
  ANTHROPIC_API_KEY="$(cat /run/secrets/anthropic_api_key)"
  export ANTHROPIC_API_KEY
fi

if [ -f /run/secrets/openai_api_key ]; then
  OPENAI_API_KEY="$(cat /run/secrets/openai_api_key)"
  export OPENAI_API_KEY
fi

if [ -z "${LITELLM_MASTER_KEY:-}" ]; then
  echo "litellm: LITELLM_MASTER_KEY is empty" >&2
  exit 1
fi

# The LiteLLM image is read-only at runtime. Give its Python/Prisma runtime the
# writable paths it needs under /tmp (mounted as tmpfs by Compose).
export HOME="${HOME:-/tmp}"
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-/tmp/litellm/cache}"
export PRISMA_BINARY_CACHE_DIR="${PRISMA_BINARY_CACHE_DIR:-/tmp/litellm/prisma}"
export LITELLM_MIGRATION_DIR="${LITELLM_MIGRATION_DIR:-/tmp/litellm/migrations}"
export LITELLM_UI_PATH="${LITELLM_UI_PATH:-/tmp/litellm/ui}"
export LITELLM_ASSETS_PATH="${LITELLM_ASSETS_PATH:-/tmp/litellm/assets}"
mkdir -p "$XDG_CACHE_HOME" "$PRISMA_BINARY_CACHE_DIR" "$LITELLM_MIGRATION_DIR" "$LITELLM_UI_PATH" "$LITELLM_ASSETS_PATH"

exec litellm --config /etc/litellm/config.json --host 0.0.0.0 --port "${LITELLM_PORT:-24000}" --num_workers 1
