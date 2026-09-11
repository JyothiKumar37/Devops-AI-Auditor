# syntax=docker/dockerfile:1
# =============================================================================
# Frontend image (development) - runs the Vite dev server with hot reload.
# The dev server proxies /api to the backend service, so the browser stays on a
# single origin. A production image would build static assets and serve them
# behind a reverse proxy; that is added when the app is deployed.
# =============================================================================

FROM node:18-alpine

WORKDIR /app

# Install dependencies first for better layer caching.
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install

COPY frontend/ ./

EXPOSE 5173

# --host exposes the dev server on all interfaces so it is reachable from the
# host machine and other containers.
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
