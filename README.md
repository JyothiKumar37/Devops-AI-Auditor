# DevOps AI Auditor

An agentic AI system that audits a complete software repository for errors,
security issues, configuration problems, DevOps best-practice violations,
reliability risks and production-readiness gaps.

> **Status: Stage 1 — Foundation.** This repository currently contains the
> production-quality application skeleton only. The scanning and analysis
> engines are intentionally **not** implemented yet; the code establishes the
> architecture they plug into.

## Planned analysis coverage

The auditor is designed to analyse the following artifact types. Each is defined
in the backend `ScannerType` enum and surfaced in the frontend catalog, but the
concrete scanners arrive in later stages:

Dockerfiles · Docker Compose · Kubernetes manifests · Helm charts · Terraform ·
GitHub Actions · GitLab CI · Jenkinsfiles · Shell scripts · Ansible ·
Configuration files · Secrets & credentials detection

## Architecture

```
devops-ai-auditor/
├── frontend/          React + TypeScript + Vite + Tailwind + Monaco dashboard
├── backend/           FastAPI API and LangGraph agent orchestration
│   ├── api/           Versioned HTTP routers and dependency wiring
│   ├── agents/        LangGraph audit orchestration graph
│   ├── scanners/      Scanner contract and registry (concrete scanners later)
│   ├── models/        SQLAlchemy models, enums, shared Pydantic schemas
│   ├── services/      Business logic
│   ├── core/          Config, logging, database/redis clients, error handling
│   ├── workers/       Celery worker and background tasks
│   └── tests/         Backend unit tests
├── docker/            Backend and frontend Dockerfiles
├── reports/           Generated audit reports (runtime)
├── scripts/           Developer helper scripts
├── tests/             Cross-service / end-to-end tests
├── docker-compose.yml Development stack (postgres, redis, backend, worker, frontend)
├── .env.example       Environment variable template
└── Makefile           Developer task runner
```

### Technology

| Layer         | Stack                                                             |
| ------------- | ----------------------------------------------------------------- |
| Frontend      | React, TypeScript, Vite, Tailwind CSS, Monaco Editor, React Query |
| Backend       | Python, FastAPI, Pydantic, SQLAlchemy (async)                     |
| Orchestration | LangGraph                                                         |
| Persistence   | PostgreSQL                                                        |
| Cache / broker| Redis                                                             |
| Workers       | Celery                                                            |

### Design principles

- **Clean, modular architecture** — scanners, agents, API routes, models and
  frontend components are independent and unit-testable.
- **Environment-based configuration** — no secrets or environment-specific
  values are hardcoded (see `.env.example`).
- **Structured logging** — JSON in production, readable console locally.
- **Consistent error handling** — a single error envelope across the API.
- **API versioning** — routes are served under `/api/v1`.
- **Graceful health reporting** — liveness and readiness probes; readiness
  reports per-dependency status and never crashes when a dependency is down.

## Getting started

### Prerequisites

- Docker and Docker Compose (for the full containerised stack), **or**
- Python 3.11+ and Node.js 18+ (to run the services directly)

### 1. Configure the environment

```bash
cp .env.example .env
# set POSTGRES_PASSWORD (required) and review other values
```

### 2a. Run with Docker (recommended)

```bash
make up          # build and start postgres, redis, backend, worker, frontend
# Frontend: http://localhost:5173
# Backend:  http://localhost:8000  (docs at /docs)
make down        # stop everything
```

### 2b. Run locally without Docker

```bash
make install         # backend venv + frontend deps
make backend-dev     # API on http://localhost:8000
make frontend-dev    # dashboard on http://localhost:5173
```

The frontend dev server proxies `/api` to the backend, so the browser stays on a
single origin.

## API

| Method | Path                     | Description                              |
| ------ | ------------------------ | ---------------------------------------- |
| GET    | `/`                      | Service metadata                         |
| GET    | `/api/v1/health/live`    | Liveness probe                           |
| GET    | `/api/v1/health/ready`   | Readiness probe with per-dependency state|
| GET    | `/docs`                  | Interactive API documentation (Swagger)  |

## Testing

```bash
make backend-test     # backend unit tests (pytest)
make frontend-build   # frontend type-check + production build
./scripts/verify.sh   # run both
```

## License

Apache-2.0
