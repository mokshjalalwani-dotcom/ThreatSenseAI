# ═══════════════════════════════════════════════════════════════════════════════
#  THREAT-SENSE AI — Makefile
#  Targets work on Linux/macOS and Windows (Git Bash / WSL).
#  On native PowerShell use the equivalent commands listed in the comments.
# ═══════════════════════════════════════════════════════════════════════════════

BACKEND_DIR := backend
PYTHON      := python
PYTEST      := $(PYTHON) -m pytest
RUFF        := $(PYTHON) -m ruff

.DEFAULT_GOAL := help
.PHONY: help run run-local down down-volumes install test test-cov lint lint-fix \
        format migrate migrate-down migrate-create shell clean

# ── Help ───────────────────────────────────────────────────────────────────────
help:
	@echo ""
	@echo "  THREAT-SENSE AI — available make targets"
	@echo "  ─────────────────────────────────────────"
	@echo "  run            Build and start all Docker services"
	@echo "  run-local      Start the API locally (no Docker) with --reload"
	@echo "  down           Stop Docker services"
	@echo "  down-volumes   Stop Docker services and delete volumes"
	@echo "  install        pip install backend in editable mode with dev extras"
	@echo "  test           Run pytest (requires install)"
	@echo "  test-cov       Run pytest with HTML coverage report"
	@echo "  lint           Run ruff linter"
	@echo "  lint-fix       Run ruff linter with auto-fix"
	@echo "  format         Run ruff formatter"
	@echo "  migrate        Apply Alembic migrations (alembic upgrade head)"
	@echo "  migrate-down   Revert one Alembic migration"
	@echo "  migrate-create MSG=<msg>  Create a new Alembic revision"
	@echo "  clean          Remove __pycache__, .ruff_cache, .pytest_cache, etc."
	@echo ""

# ── Docker ─────────────────────────────────────────────────────────────────────
run:
	docker compose up --build

run-detached:
	docker compose up --build -d

down:
	docker compose down

down-volumes:
	docker compose down -v

# ── Local development (no Docker required — uses SQLite) ───────────────────────
install:
	cd $(BACKEND_DIR) && $(PYTHON) -m pip install -e ".[dev]"

run-local:
	cd $(BACKEND_DIR) && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# ── Testing ────────────────────────────────────────────────────────────────────
test:
	cd $(BACKEND_DIR) && $(PYTEST) tests/ -v --tb=short

test-cov:
	cd $(BACKEND_DIR) && $(PYTEST) tests/ -v --cov=app --cov-report=term-missing --cov-report=html

# ── Linting / Formatting ──────────────────────────────────────────────────────
lint:
	cd $(BACKEND_DIR) && $(RUFF) check app/ tests/

lint-fix:
	cd $(BACKEND_DIR) && $(RUFF) check --fix app/ tests/

format:
	cd $(BACKEND_DIR) && $(RUFF) format app/ tests/

# ── Database ───────────────────────────────────────────────────────────────────
migrate:
	cd $(BACKEND_DIR) && alembic upgrade head

migrate-down:
	cd $(BACKEND_DIR) && alembic downgrade -1

migrate-create:
	cd $(BACKEND_DIR) && alembic revision --autogenerate -m "$(MSG)"

# ── Utilities ──────────────────────────────────────────────────────────────────
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; true
	find . -type f -name "*.pyc" -delete 2>/dev/null; true
	find . -type f -name "*.pyo" -delete 2>/dev/null; true
	rm -rf $(BACKEND_DIR)/.ruff_cache \
	       $(BACKEND_DIR)/.pytest_cache \
	       $(BACKEND_DIR)/htmlcov \
	       $(BACKEND_DIR)/.coverage \
	       $(BACKEND_DIR)/threatsense.db
