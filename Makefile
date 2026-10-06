# AdaptShield Makefile

PYTHON ?= python

.PHONY: help data train test

help:
	@echo "AdaptShield Commands:"
	@echo "  make data   - Generate reproducible synthetic datasets and scenarios"
	@echo "  make train  - Train and register all benchmark and ablation models"
	@echo "  make test   - Run all pytest unit tests"

data:
	$(PYTHON) scripts/make_datasets.py

train:
	$(PYTHON) scripts/train_all.py

test:
	$(PYTHON) -m pytest tests/ -v
