#!/usr/bin/env bash
# Run the foundation's automated checks: backend tests and frontend build.
# Intended for local use and CI. Requires the backend venv and frontend deps
# to be installed (see `make install`).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> Backend: running unit tests"
(cd "${ROOT_DIR}/backend" && .venv/bin/pytest -q)

echo "==> Frontend: type-check and build"
(cd "${ROOT_DIR}/frontend" && npm run build)

echo "==> All checks passed"
