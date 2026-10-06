# AdaptShield Makefile

PYTHON ?= python

.PHONY: help data train test test-backend test-frontend demo docker-up docker-down clean

help:
	@echo "AdaptShield Fullstack Demo Targets:"
	@echo "  make data          - Generate reproducible synthetic datasets and scenarios"
	@echo "  make train         - Train and register all benchmark and ablation models"
	@echo "  make test          - Run both backend pytest and frontend vitest suites"
	@echo "  make test-backend  - Run Python pytest tests across ML, core, and API"
	@echo "  make test-frontend - Run frontend unit and component tests via Vitest"
	@echo "  make demo          - Launch fullstack backend and frontend development servers"
	@echo "  make docker-up     - Start backend and frontend via Docker Compose"
	@echo "  make docker-down   - Stop Docker Compose services"
	@echo "  make clean         - Remove pycache, build artifacts, and caches"

data:
	$(PYTHON) scripts/make_datasets.py

train:
	$(PYTHON) scripts/train_all.py

test-backend:
	$(PYTHON) -m pytest tests/ -v

test-frontend:
	npm --prefix frontend test -- --run

test: test-backend test-frontend

demo:
	@echo "Starting AdaptShield demo..."
	@echo "Backend will run at http://localhost:8000"
	@echo "Frontend will run at http://localhost:5173"
	$(PYTHON) -m uvicorn backend.app.main:app --port 8000 --host 0.0.0.0

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .pytest_cache frontend/dist 2>/dev/null || true

