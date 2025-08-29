# Vulnerability Analyzer Development Commands
# Use with: make <target>

.PHONY: help install test lint type-check security clean format

help:
	@echo "Available commands:"
	@echo "  install     - Install dependencies"
	@echo "  test        - Run all tests"
	@echo "  test-perf   - Run performance benchmarks"
	@echo "  lint        - Run code linting"
	@echo "  type-check  - Run type checking with mypy"
	@echo "  security    - Run security analysis with bandit"
	@echo "  format      - Format code with black and isort"
	@echo "  clean       - Clean cache and temp files"
	@echo "  pre-commit  - Install pre-commit hooks"

install:
	uv sync --dev

test:
	uv run pytest

test-perf:
	uv run pytest tests/test_performance.py -v -s

test-cov:
	uv run pytest --cov=models --cov=parsers --cov-report=html

lint:
	uv run black --check .
	uv run isort --check-only .

type-check:
	uv run mypy models parsers

security:
	uv run bandit -r models parsers

format:
	uv run black .
	uv run isort .

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .coverage htmlcov/ .pytest_cache/ .mypy_cache/

pre-commit:
	uv run pre-commit install

# Run full quality checks
check-all: lint type-check security test
	@echo "All checks passed!"
