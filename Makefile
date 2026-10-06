# AdaptShield Makefile

PYTHON ?= python

.PHONY: help data test

help:
	@echo "AdaptShield Commands:"
	@echo "  make data   - Generate reproducible synthetic datasets and scenarios"
	@echo "  make test   - Run all pytest unit tests"

data:
	$(PYTHON) scripts/make_datasets.py

test:
	$(PYTHON) -m pytest tests/ -v
