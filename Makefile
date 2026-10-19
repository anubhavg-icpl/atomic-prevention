.PHONY: build run stop wait sync dev-backend dev-frontend install-backend install-frontend clean push

API_URL ?= http://localhost:3000
IMAGE ?= ghcr.io/anubhavg-icpl/atomic-prevention:latest

# Container targets
build:
	docker compose build

run:
	docker compose up -d

stop:
	docker compose down

logs:
	docker compose logs -f

wait:
	@echo "Waiting for Atomic Prevention at $(API_URL)..."
	@until curl -fsS "$(API_URL)/api/health" >/dev/null; do sleep 2; done
	@echo "Atomic Prevention is ready."

# Sync all LOL data sources
sync: wait
	@echo "Syncing all data sources..."
	@curl -fsS -X POST "$(API_URL)/api/sources/lolbas/sync" | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'  LOLBAS: {d[\"tests_persisted\"]} tests')"
	@curl -fsS -X POST "$(API_URL)/api/sources/atomic-red-team/sync" | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'  Atomic Red Team: {d[\"tests_persisted\"]} tests')"
	@curl -fsS -X POST "$(API_URL)/api/sources/loldrivers/sync" | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'  LOLDrivers: {d[\"tests_persisted\"]} tests')"
	@curl -fsS -X POST "$(API_URL)/api/sources/lolrmm/sync" | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'  LOLRMM: {d[\"tests_persisted\"]} tests')"
	@curl -fsS -X POST "$(API_URL)/api/sources/loobins/sync" | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'  LOOBins: {d[\"tests_persisted\"]} tests')"
	@curl -fsS -X POST "$(API_URL)/api/sources/lolapi/sync" | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'  LOLAPI: {d[\"tests_persisted\"]} tests')"
	@curl -fsS -X POST "$(API_URL)/api/sources/lottunnels/sync" | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'  LOTTunnels: {d[\"tests_persisted\"]} tests')"
	@curl -fsS -X POST "$(API_URL)/api/sources/persistence-info/sync" | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'  Persistence-Info: {d[\"tests_persisted\"]} tests')"
	@curl -fsS -X POST "$(API_URL)/api/sources/gtfobins/sync" | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'  GTFOBins: {d[\"tests_persisted\"]} tests')"
	@curl -fsS -X POST "$(API_URL)/api/sources/loas/sync" | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'  LOAS: {d[\"tests_persisted\"]} tests')"
	@curl -fsS -X POST "$(API_URL)/api/sources/sysinternals/sync" | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'  Sysinternals: {d[\"tests_persisted\"]} tests')"
	@echo "Done! Check stats at $(API_URL)/api/techniques/stats"

# Local development targets
install-backend:
	cd backend && pip install -r requirements.txt

install-frontend:
	cd frontend && npm install

dev-backend:
	cd backend && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

dev-frontend:
	cd frontend && npm run dev

# Run both locally
dev:
	@echo "Start backend and frontend in separate terminals:"
	@echo "  make dev-backend"
	@echo "  make dev-frontend"

# Clean up
clean:
	docker compose down -v
	rm -rf backend/data backend/atomic_prevention.db
	rm -rf frontend/.next frontend/node_modules

# Push images to GHCR (requires docker login to ghcr.io)
push:
	docker build -t "$(IMAGE)" .
	docker push "$(IMAGE)"
