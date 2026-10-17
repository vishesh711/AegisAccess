# AegisAccess developer commands. Requires: docker (compose v2), uv.
SHELL := /bin/bash
COMPOSE := docker compose -f infra/compose.yaml $(if $(wildcard .env),--env-file .env,)
OPA_IMAGE := openpolicyagent/opa:1.4.2-static@sha256:3c995dc8a59f6ddfd92eb7404d2f7ff9fe71cd025d9251199957a8a6afbfd76e
UV := uv run
# Optional: AEGIS_EXTRA_CA=/path/ca.pem  (TLS-intercepting proxy during image build only)

.PHONY: help install up down migrate seed lint test unit policy-test integration security-test sql-eval demo logs reset audit-deps audit-ship audit-verify up-hardened seed-hardened hardened-test pki

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
	$(COMPOSE) -f infra/compose.hardened.yaml down -v --remove-orphans

# Hardened profile (ADR-9): HTTPS-only Keycloak on PostgreSQL, PKCE logins, mutual TLS to OPA.
COMPOSE_HARDENED := $(COMPOSE) -f infra/compose.hardened.yaml

pki:
	$(UV) python scripts/gen_pki.py
	$(UV) python scripts/harden_realm.py

up-hardened: .build/extra-ca.crt pki
	$(COMPOSE_HARDENED) up -d --build --wait --wait-timeout 300

# Principals are bound to (issuer, subject); the hardened Keycloak issues tokens as https://localhost:8443.
seed-hardened:
	AEGIS_OIDC_ISSUER=https://localhost:8443/realms/aegis $(MAKE) seed

hardened-test:
	$(UV) pytest tests/hardened -q -m hardened

logs:
	$(COMPOSE) logs --no-color --tail=200

migrate:
	$(UV) python scripts/migrate.py up

seed:
	$(UV) python scripts/seed.py
	$(UV) python scripts/audit_sink_setup.py

# Ship pending audit events now (the compose audit-shipper service also does this every few seconds).
audit-ship:
	AEGIS_AUDIT_SHIPPER_DATABASE_URL=$${AEGIS_AUDIT_SHIPPER_DATABASE_URL:-postgresql://aegis_audit_shipper:dummy-aegis-shipper-pw@127.0.0.1:5432/aegis} \
	  $(UV) python -m aegis.audit_sink --once

# Verify the external audit store and reconcile it with the database. SINCE limits the activity checks.
audit-verify:
	@mkdir -p artifacts/tmp
	$(UV) python scripts/audit_verify.py --activity-since $${SINCE:-24h} --json artifacts/tmp/audit-verify.json

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
	$(UV) pytest tests/security -q
	$(UV) python scripts/security_report.py

test: policy-test
	$(UV) pytest tests -q

sql-eval:
	$(UV) python scripts/sql_eval.py

demo:
	$(UV) python scripts/demo.py

audit-deps:
	$(UV) pip-audit -r requirements.lock --require-hashes --disable-pip
