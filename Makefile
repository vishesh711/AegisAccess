# AegisAccess developer commands. Requires: docker (compose v2), uv.
SHELL := /bin/bash
COMPOSE := docker compose -f infra/compose.yaml $(if $(wildcard .env),--env-file .env,)
OPA_IMAGE := openpolicyagent/opa:1.4.2-static@sha256:3c995dc8a59f6ddfd92eb7404d2f7ff9fe71cd025d9251199957a8a6afbfd76e
UV := uv run
# Optional: AEGIS_EXTRA_CA=/path/ca.pem  (TLS-intercepting proxy during image build only)

.PHONY: help install up down migrate seed lint test unit policy-test integration security-test sql-eval demo logs reset

help:
	@grep -E '^[a-z-]+:' Makefile | cut -d: -f1 | sort | tr '\n' ' '; echo

install:
	uv sync --frozen

.build/extra-ca.crt:
	@mkdir -p .build
	@if [ -n "$$AEGIS_EXTRA_CA" ]; then cp "$$AEGIS_EXTRA_CA" .build/extra-ca.crt; else : > .build/extra-ca.crt; fi

up: .build/extra-ca.crt
	$(COMPOSE) up -d --build --wait --wait-timeout 300

down:
	$(COMPOSE) down -v --remove-orphans

logs:
	$(COMPOSE) logs --no-color --tail=200

migrate:
	$(UV) python scripts/migrate.py up

seed:
	$(UV) python scripts/seed.py

reset: down up migrate seed

lint:
	$(UV) ruff check .
	$(UV) ruff format --check .
	$(UV) mypy
	docker run --rm -v $(CURDIR)/policies:/policies:ro $(OPA_IMAGE) fmt --list --fail /policies
	docker run --rm -v $(CURDIR)/policies:/policies:ro $(OPA_IMAGE) check --strict /policies

policy-test:
	docker run --rm -v $(CURDIR)/policies:/policies:ro $(OPA_IMAGE) test /policies -v

unit:
	$(UV) pytest tests/unit -q

integration:
	$(UV) pytest tests/integration -q

security-test:
	$(UV) pytest tests/security -q -p tests.security.recorder
	$(UV) python scripts/security_report.py

test: policy-test
	$(UV) pytest tests -q

sql-eval:
	$(UV) python scripts/sql_eval.py

demo:
	$(UV) python scripts/demo.py
