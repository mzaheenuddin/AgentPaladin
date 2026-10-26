.PHONY: help init secrets preflight build reload agent shell verify export audit scan models ollama down logs clean compile

help:
	@echo "Agent Paladin targets:"
	@echo "  make init       initialize generated gateway/proxy secrets"
	@echo "  make secrets    list secret file status"
	@echo "  make preflight  check host/Docker prerequisites"
	@echo "  make build      build all local container images"
	@echo "  make reload     recreate proxy services after config changes"
	@echo "  make agent      launch the default snapshot + no-egress run"
	@echo "  make shell      launch a shell inside a sandbox run"
	@echo "  make verify     run the host + sandbox security verification"
	@echo "  make export     generate a patch from the latest snapshot run"
	@echo "  make audit      audit changes in the latest direct-mount project"
	@echo "  make scan       scan the configured project for secret patterns"
	@echo "  make models     render and list available models"
	@echo "  make ollama     manage the optional local Ollama service"
	@echo "  make down       stop the compose project"
	@echo "  make logs       follow compose logs"
	@echo "  make clean      remove old runs (keeps 5)"
	@echo "  make compile    byte-compile the Python scripts"

init:
	./bin/secrets init

secrets:
	./bin/secrets list

preflight:
	./bin/preflight

build:
	./bin/build

reload:
	./bin/reload

agent:
	./bin/agent

shell:
	./bin/shell

verify:
	./bin/verify

export:
	./bin/export

audit:
	./bin/audit

scan:
	./bin/scan

models:
	./bin/models

ollama:
	./bin/ollama

down:
	./bin/down

logs:
	./bin/logs

clean:
	./bin/clean

compile:
	python3 -m py_compile bin/paladin bin/agent bin/build bin/clean bin/down bin/egress bin/logs bin/ollama bin/reload bin/scan bin/secrets bin/verify scripts/*.py docker/prompt-dlp/*.py docker/egress-broker/*.py
