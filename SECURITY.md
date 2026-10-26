# Security policy

Agent Paladin is a hardening tool for running autonomous coding agents. It is
not a guarantee that a host, credential, or repository cannot be compromised.
See the "License, third-party components, and disclaimer" section in
`README.md` and Sections 7 and 8 of the Apache-2.0 license.

## Supported versions

Security fixes are applied to the latest release and the `main` branch. Older
versions are not guaranteed to receive fixes.

## Reporting a vulnerability

Please do **not** open a public issue for an undisclosed vulnerability.

Use GitHub's private vulnerability reporting for this repository (Security →
Report a vulnerability). If private reporting is unavailable, contact the
maintainer through the repository's published contact method and include:

* a short description of the issue and its impact;
* the affected version or commit;
* reproduction steps or a proof of concept;
* any suggested mitigation.

Do not include real credentials, customer data, or third-party data in a
report. Use synthetic values. The maintainer will acknowledge reports on a
best-effort basis; no response-time SLA is offered.

## Scope

In scope:

* container escapes or isolation bypasses in the supplied configuration;
* sandbox network/DNS/firewall bypasses;
* secret exposure through the gateway, DLP proxy, broker, or logs;
* path traversal, symlink, or export-gate bypasses;
* vulnerabilities in the host-side Python/shell code in this repository.

Out of scope:

* vulnerabilities in Docker, the host kernel, OpenCode, LiteLLM, Caddy, Squid,
  Ollama, model providers, or model weights (report those upstream);
* prompt injection that does not cross a documented boundary;
* misconfiguration that the operator was warned about;
* denial of service caused by intentionally extreme resource settings;
* social engineering or physical access.

## Safe testing

Only test on systems you own or are explicitly authorized to test. Do not use
the egress broker or any other part of this project to access systems without
authorization. Do not test with real customer data or live credentials.

## No warranty

This software is provided "AS IS", without warranty of any kind, express or
implied. To the maximum extent permitted by law, the maintainer is not liable
for data loss, credential exposure, service interruption, or other damages
arising from use of the software. You are responsible for backups, code review,
provider terms, and compliance with applicable law. See Sections 7 and 8 of the
Apache-2.0 license.
