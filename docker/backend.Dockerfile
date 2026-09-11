# syntax=docker/dockerfile:1
# =============================================================================
# Backend image - the FastAPI API and the Celery worker share this image.
# Multi-stage build keeps the runtime lean and runs as a non-root user.
# =============================================================================

FROM python:3.11-slim AS base
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app

# ---- Builder: install the project and its dependencies ----
FROM base AS builder
# The project's packages are declared in pyproject.toml, so the source must be
# present for the install to resolve them.
COPY backend/ /app/
RUN pip install --upgrade pip && pip install .

# ---- Runtime ----
FROM base AS runtime
# Bring in installed packages and console scripts (uvicorn, celery) from builder.
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Run as an unprivileged user.
RUN groupadd --system app && useradd --system --gid app --home /app app

COPY backend/ /app/
RUN chown -R app:app /app
USER app

EXPOSE 8000

# Default command runs the API; the worker service overrides this in compose.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
