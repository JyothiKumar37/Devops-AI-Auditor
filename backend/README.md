# Backend — DevOps AI Auditor

FastAPI service and LangGraph agent orchestration for the DevOps AI Repository
Auditor.

## Layout

| Package     | Responsibility                                                        |
| ----------- | --------------------------------------------------------------------- |
| `core/`     | Config, structured logging, database/redis clients, error handling.   |
| `api/`      | Versioned HTTP routers and dependency wiring.                         |
| `models/`   | SQLAlchemy models, enums and shared Pydantic schemas.                 |
| `services/` | Business logic (kept out of route handlers).                          |
| `scanners/` | Scanner contract and registry (concrete scanners added later).        |
| `agents/`   | LangGraph audit orchestration graph.                                  |
| `workers/`  | Celery worker and background tasks.                                   |
| `tests/`    | Unit tests.                                                           |

## Local development

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/uvicorn main:app --reload
```

Run the tests:

```bash
.venv/bin/pytest
```
