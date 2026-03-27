.PHONY: install dev test lint format run clean

install:
	pip install -e .

dev:
	pip install -e ".[dev]" 2>/dev/null || pip install -e .
	pip install pytest pytest-asyncio ruff mypy

test:
	python -m pytest tests/ -v --tb=short

test-unit:
	python -m pytest tests/unit/ -v --tb=short

test-integration:
	python -m pytest tests/integration/ -v --tb=short

lint:
	ruff check blanketaudit/ tests/
	mypy blanketaudit/ --ignore-missing-imports

format:
	ruff format blanketaudit/ tests/
	ruff check --fix blanketaudit/ tests/

run:
	blanketaudit scan --help

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf .ruff_cache .mypy_cache dist build
