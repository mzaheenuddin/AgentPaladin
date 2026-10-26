# Third-party notices and distribution notes

Agent Paladin's source repository does not vendor third-party source code. The
host-side Python code uses only the Python standard library. The container-side
Python code also uses only the standard library; the shell scripts use the
operating-system packages described below.

At build and run time, however, the project uses third-party container images,
operating-system packages, model providers, and model weights. Those components
remain under their own licenses and terms; the Apache-2.0 license in `LICENSE`
does not relicense them.

This file is a practical inventory, not a substitute for the license text that
ships with each component.

## Container images and packages

| Component | Used by | License | Distribution note |
|---|---|---|---|
| [OpenCode](https://github.com/anomalyco/opencode) (`ghcr.io/anomalyco/opencode`) | `sandbox` image | MIT (plus bundled dependencies under their own licenses) | Pulled as a base image. The repository does not redistribute it. |
| [LiteLLM](https://github.com/BerriAI/litellm) (`docker.litellm.ai/berriai/litellm`) | `llm-proxy` image | MIT for content outside `enterprise/`; `enterprise/` has a separate license (plus bundled dependencies) | Pulled as a base image. The repository does not redistribute it. Review LiteLLM's enterprise terms if you use or redistribute enterprise features. |
| [Caddy](https://github.com/caddyserver/caddy) (`caddy:2.10-alpine`) | `llm-gateway` image | Apache-2.0 (plus bundled dependencies) | Pulled as a base image. Caddy's own notices apply if you redistribute a built image. |
| [Squid](https://github.com/squid-cache/squid) (`squid` Alpine package) | `llm-egress` and `sandbox-egress` images | GPL-2.0 | Installed by `docker/egress/Dockerfile`. The repository only provides a Dockerfile and config; it does not distribute the Squid binary. See the GPL note below. |
| [Alpine Linux](https://alpinelinux.org/) (`alpine`, `python:3.12-alpine`) | Base images | Mixed (MIT, BSD, GPL, LGPL, and others) | The packages in a built image keep their own licenses. If you publish a built image, include the relevant notices and source offers. |
| [Python](https://www.python.org/) | `python:3.12-alpine` base | PSF-2.0 | Included in the base image. |
| [Ollama](https://github.com/ollama/ollama) (`ollama/ollama`) | Optional local model service | MIT (plus bundled dependencies) | Optional; not required for cloud-provider profiles. Model weights are separate. |

### GPL note for built images

If you build and distribute container images from this repository, you are
distributing the third-party packages inside those images. In particular:

* the egress images contain Squid, which is licensed under GPL-2.0;
* the sandbox image contains Alpine packages such as Git (GPL-2.0) and Bash
  (GPL-3.0), in addition to OpenCode (MIT).

GPL-2.0 and GPL-3.0 require you to provide the corresponding source and license
notices when you distribute the binaries. The Apache-2.0 license of Agent
Paladin does not replace those obligations. Apache-2.0 is compatible with
GPL-3.0, but it is not compatible with GPL-2.0-only for a combined work. Keep
GPL components in separate images/processes as this repository does, do not
relicense them, and do not describe a built image as "Apache-2.0 only".

The repository itself is source-only and does not publish prebuilt images. If
that changes, add the third-party license texts and a GPL source offer to the
published artifacts.

## Model providers and model weights

Agent Paladin does not include provider API keys or model weights. The operator
supplies keys and chooses providers.

| Component | License / terms | Note |
|---|---|---|
| DeepSeek API | DeepSeek terms of service | Prompts and code are sent to DeepSeek when that provider is selected. |
| Anthropic API | Anthropic terms of service | Prompts and code are sent to Anthropic when that provider is selected. |
| OpenAI API | OpenAI terms of service | Prompts and code are sent to OpenAI when that provider is selected. |
| Qwen3 Coder and other Ollama models | Separate model licenses | Model weights are pulled by the operator; they are not part of this repository. Check the model's license before redistribution or commercial use. |

You are responsible for confirming that you have the right to send the code,
data, and prompts you use to each provider, and for complying with the
provider's terms and any applicable data-protection law.

## Artwork and documentation assets

| Asset | Status |
|---|---|
| `assets/security-architecture.png` | The names DeepSeek, Anthropic, OpenAI, Docker, Squid, Caddy, LiteLLM, and OpenCode are used nominatively for identification only. See `NOTICE`. |
| Text and diagrams in `README.md` and `docs/` | Project documentation, licensed under Apache-2.0 except third-party names and marks. Produced with AI assistance. |

If you are a rights holder and believe an asset is used incorrectly, open an
issue or contact the maintainer so it can be reviewed or removed.

## Test fixtures and example credentials

`bin/verify` contains a deliberately fake AWS-style key used to test the
secret scanner. It is not a real credential. Other examples in the
documentation use placeholder values.

## No legal advice

This inventory is provided for convenience and does not constitute legal
advice. License and trademark questions should be reviewed by qualified counsel
before commercial distribution.
