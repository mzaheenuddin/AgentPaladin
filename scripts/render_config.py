#!/usr/bin/env python3
"""Render LiteLLM and OpenCode configuration from config/models.json."""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path

from common import ROOT, config, fail, generated_dir


def secret_available(secret: str | None) -> bool:
    if not secret:
        return True
    path = ROOT / "secrets" / secret
    try:
        return path.is_file() and path.stat().st_size > 0
    except OSError:
        return False


def build_litellm(models: list[dict]) -> dict:
    model_list = []
    for model in models:
        params: dict[str, object] = {"model": model["upstream"]}
        if model.get("secret"):
            params["api_key"] = f"os.environ/{model['secret']}"
        if model.get("apiBase"):
            params["api_base"] = model["apiBase"]
        model_list.append({"model_name": model["alias"], "litellm_params": params})

    return {
        "model_list": model_list,
        "litellm_settings": {
            "drop_params": True,
            "request_timeout": 900,
            "json_logs": True,
            "turn_off_message_logging": True,
            "disable_hf_tokenizer_download": True,
            "redact_user_api_key_info": True,
        },
        "general_settings": {
            "master_key": "os.environ/LITELLM_MASTER_KEY",
            "disable_spend_logs": True,
            "disable_error_logs": True,
            "disable_master_key_return": True,
            "trusted_proxy_ranges": [],
        },
    }


def build_opencode(base: dict, models: list[dict], default: str) -> dict:
    rendered = copy.deepcopy(base)
    rendered["model"] = f"litellm/{default}"
    providers = rendered.setdefault("providers", {})
    litellm = providers.setdefault("litellm", {})
    litellm_models: dict[str, object] = {}
    for model in models:
        entry: dict[str, object] = {
            "name": model.get("name", model["alias"]),
            "limit": model.get("limit", {}),
            "capabilities": model.get("capabilities", {}),
        }
        if model.get("cacheFormat"):
            entry["compatibility"] = {"cacheFormat": model["cacheFormat"]}
        litellm_models[model["alias"]] = entry
    litellm["models"] = litellm_models
    return rendered


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--models", default=str(ROOT / "config" / "models.json"))
    parser.add_argument("--base", default=str(ROOT / "config" / "opencode" / "base.json"))
    parser.add_argument("--out", default=str(generated_dir()))
    parser.add_argument("--default", default=None)
    parser.add_argument("--profile", default="edit")
    parser.add_argument("--local-only", action="store_true")
    parser.add_argument("--include-local", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    cfg = config()
    models_path = Path(args.models)
    base_path = Path(args.base)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        manifest = json.loads(models_path.read_text(encoding="utf-8"))
        base = json.loads(base_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read model configuration: {exc}")

    local_only = args.local_only or args.profile == "local"
    chosen: list[dict] = []
    missing: list[dict] = []
    for model in manifest.get("models", []):
        is_local = bool(model.get("localOnly"))
        if local_only and not is_local:
            continue
        if not local_only and is_local and not args.include_local:
            continue
        if not secret_available(model.get("secret")):
            missing.append(
                {
                    "alias": model.get("alias"),
                    "secret": model.get("secret"),
                    "reason": f"secrets/{model.get('secret')} is missing or empty",
                }
            )
            continue
        chosen.append(model)

    if not chosen:
        print("No models are available.", file=sys.stderr)
        for item in missing:
            print(f"  missing: {item['alias']} ({item['reason']})", file=sys.stderr)
        print(
            "Set a provider key with: bin/secrets set DEEPSEEK_API_KEY",
            file=sys.stderr,
        )
        return 1

    requested_default = args.default or cfg.get("DEFAULT_MODEL") or manifest.get("default")
    available_aliases = [model["alias"] for model in chosen]
    if requested_default not in available_aliases:
        fallback = manifest.get("default")
        if fallback in available_aliases:
            requested_default = fallback
        else:
            requested_default = available_aliases[0]
        print(
            f"warning: requested model is unavailable; using {requested_default}",
            file=sys.stderr,
        )
    default = requested_default

    if args.check:
        print(f"configuration is valid; default model: {default}")
        print(f"available models: {', '.join(available_aliases)}")
        return 0

    litellm_config = build_litellm(chosen)
    opencode_config = build_opencode(base, chosen, default)

    litellm_path = out_dir / "litellm.json"
    opencode_path = out_dir / "opencode.json"
    available_path = out_dir / "available.json"
    litellm_path.write_text(json.dumps(litellm_config, indent=2) + "\n", encoding="utf-8")
    opencode_path.write_text(json.dumps(opencode_config, indent=2) + "\n", encoding="utf-8")
    available_path.write_text(
        json.dumps(
            {
                "default": default,
                "available": available_aliases,
                "missing": missing,
                "profile": args.profile,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    print(f"default model: {default}")
    print(f"available models: {', '.join(available_aliases)}")
    if missing:
        print("unavailable models:")
        for item in missing:
            print(f"  - {item['alias']}: {item['reason']}")
    print(f"wrote {litellm_path}")
    print(f"wrote {opencode_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
