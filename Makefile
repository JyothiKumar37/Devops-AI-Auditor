# =============================================================================
# DevOps AI Auditor - Developer Task Runner
# =============================================================================
# Run `make help` to see available targets.

SHELL := /bin/bash
COMPOSE := docker compose
BACKEND_DIR := backend
FRONTEND_DIR := frontend

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help message
	@grep -E '^[a-zA-Z0-9_.-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ---- Environment ----
.PHONY: env
env: ## Create a .env file from .env.example if it does not exist
	@test -f .env || (cp .env.example .env && echo "Created .env from .env.example")

# ---- Docker development environment ----
.PHONY: up
up: env ## Start the full stack (postgres, redis, backend, worker, frontend)
	$(COMPOSE) up --build

.PHONY: up-d
up-d: env ## Start the full stack in the background
	$(COMPOSE) up --build -d

.PHONY: down
down: ## Stop and remove all containers
	$(COMPOSE) down

.PHONY: logs
logs: ## Tail logs from all services
	$(COMPOSE) logs -f

.PHONY: ps
ps: ## Show running services
	$(COMPOSE) ps

# ---- Backend ----
.PHONY: backend-install
backend-install: ## Install backend Python dependencies into a local venv
	cd $(BACKEND_DIR) && python3 -m venv .venv && \
		.venv/bin/pip install --upgrade pip && \
		.venv/bin/pip install -e ".[dev]"

.PHONY: backend-dev
backend-dev: ## Run the backend API locally with autoreload
	cd $(BACKEND_DIR) && .venv/bin/uvicorn main:app --reload --host 0.0.0.0 --port 8000

.PHONY: backend-worker
backend-worker: ## Run a background worker locally
	cd $(BACKEND_DIR) && .venv/bin/celery -A workers.celery_app.celery_app worker --loglevel=info

.PHONY: backend-test
backend-test: ## Run backend unit tests
	cd $(BACKEND_DIR) && .venv/bin/pytest

.PHONY: backend-lint
backend-lint: ## Lint and type-check the backend
	cd $(BACKEND_DIR) && .venv/bin/ruff check . && .venv/bin/mypy .

# ---- Frontend ----
.PHONY: frontend-install
frontend-install: ## Install frontend dependencies
	cd $(FRONTEND_DIR) && npm install

.PHONY: frontend-dev
frontend-dev: ## Run the frontend dev server
	cd $(FRONTEND_DIR) && npm run dev

.PHONY: frontend-build
frontend-build: ## Build the frontend for production
	cd $(FRONTEND_DIR) && npm run build

.PHONY: frontend-lint
frontend-lint: ## Lint the frontend
	cd $(FRONTEND_DIR) && npm run lint

# ---- Aggregate ----
.PHONY: install
install: backend-install frontend-install ## Install all dependencies

.PHONY: test
test: backend-test ## Run all test suites

.PHONY: clean
clean: ## Remove build artifacts and caches
	find . -type d -name "__pycache__" -prune -exec rm -rf {} + 2>/dev/null || true
	rm -rf $(BACKEND_DIR)/.pytest_cache $(BACKEND_DIR)/.mypy_cache $(BACKEND_DIR)/.ruff_cache
	rm -rf $(FRONTEND_DIR)/dist $(FRONTEND_DIR)/node_modules/.vite
