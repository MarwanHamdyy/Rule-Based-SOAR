# ============================================================
# SOAR Engine Makefile
# Usage: make <target>
# ============================================================

.PHONY: install setup run run-replay run-once test test-cov lint clean help

# Python interpreter
PYTHON := python

# Config directory
CONFIG_DIR := ./config

help:  ## Show this help message
	@echo "Rule-Based SOAR Engine - Make targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

install:  ## Install Python dependencies
	pip install -r requirements.txt

setup:  ## First-time setup: copy .env.example, create directories
	@if not exist .env (copy .env.example .env && echo Copied .env.example to .env)
	@if not exist data mkdir data
	@if not exist logs mkdir logs
	@echo Setup complete. Edit .env with your Elasticsearch credentials.

run:  ## Run engine in LIVE mode
	$(PYTHON) main.py --config-dir $(CONFIG_DIR) --mode live

run-replay:  ## Run engine in REPLAY mode (set REPLAY_FROM in .env)
	$(PYTHON) main.py --config-dir $(CONFIG_DIR) --mode replay

run-once:  ## Run a single poll cycle then exit (good for testing)
	$(PYTHON) main.py --config-dir $(CONFIG_DIR) --once

reset:  ## Delete checkpoint and restart from scratch
	$(PYTHON) main.py --config-dir $(CONFIG_DIR) --reset-checkpoint --once

test:  ## Run all unit tests
	pytest tests/ -v

test-cov:  ## Run tests with coverage report
	pytest tests/ -v --cov=. --cov-exclude=tests/ --cov-report=term-missing

lint:  ## Check code style (requires ruff or flake8)
	-ruff check . || flake8 . --max-line-length=110

clean:  ## Remove __pycache__ and .pyc files
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@find . -name "*.pyc" -delete 2>/dev/null || true
	@echo Cleaned.
