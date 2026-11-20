.PHONY: init dev-certs up down migrate backend-check backend-test backend-integration web-check endpoint-check check macos-agent-install macos-desktop macos-desktop-install

init:            ## Generate .env and dev signing keys (never overwrites)
	./scripts/dev-init.sh

dev-certs:       ## Create the dev CA + loopback TLS cert for the agent gateway (never overwrites)
	cd backend && uv run python -m app.cli dev-certs

up: dev-certs    ## Start PostgreSQL, run migrations, start backend (:8000) and agent gateway (:8443)
	mkdir -p /Users/Shared/SentinelDesk/packages
	docker compose up -d --build --wait backend agent-gateway

down:
	docker compose down

migrate:
	docker compose run --rm migrate

backend-check:   ## Format check, lint, type check
	cd backend && uv run ruff format --check . && uv run ruff check . && uv run mypy

backend-test:
	cd backend && uv run pytest -q

TEST_DB ?= sentinel_test

backend-integration:  ## Requires `make up`; creates and migrates a disposable $(TEST_DB) database
	cd endpoint && cargo build -p sentinel-agent
	cd backend && set -a && . ../.env && set +a && \
	TEST_DATABASE_URL="postgresql+asyncpg://sentinel_app:$$APP_DB_PASSWORD@localhost:5432/$(TEST_DB)" \
	TEST_MIGRATION_DATABASE_URL="postgresql+asyncpg://$$POSTGRES_USER:$$POSTGRES_PASSWORD@localhost:5432/$(TEST_DB)" \
	uv run pytest -q -m integration

web-check:
	cd web && npm run format:check && npm run typecheck && npm run lint && npm test && npm run build

endpoint-check:
	cd endpoint && cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace && cargo build --workspace

macos-agent-install: ## Build + install always-on Mac user agent + menu bar (demo)
	./scripts/install-macos-user-agent.sh

macos-desktop: ## Build shareable Sentinel.app + zip under dist/macos/
	./scripts/build-macos-desktop.sh

macos-desktop-install: ## Build (if needed) and install Sentinel.app to /Applications
	./scripts/install-macos-desktop.sh

check: backend-check backend-test web-check endpoint-check
