#!/usr/bin/env bash
# Start the backend API and frontend dev server locally (without Docker).
# PostgreSQL and Redis are expected to be running separately; the app degrades
# gracefully and reports their status via the readiness endpoint if they are not.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cleanup() {
  [[ -n "${BACKEND_PID:-}" ]] && kill "${BACKEND_PID}" 2>/dev/null || true
  [[ -n "${FRONTEND_PID:-}" ]] && kill "${FRONTEND_PID}" 2>/dev/null || true
}
trap cleanup EXIT

echo "==> Starting backend on http://localhost:8000"
(cd "${ROOT_DIR}/backend" && .venv/bin/uvicorn main:app --reload --host 0.0.0.0 --port 8000) &
BACKEND_PID=$!

echo "==> Starting frontend on http://localhost:5173"
(cd "${ROOT_DIR}/frontend" && npm run dev) &
FRONTEND_PID=$!

wait
