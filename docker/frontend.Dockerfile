# syntax=docker/dockerfile:1
# =============================================================================
# Frontend image (development) - runs the Vite dev server with hot reload.
# The dev server proxies /api to the backend service, so the browser stays on a
# single origin. A production image would build static assets and serve them
# behind a reverse proxy; that is added when the app is deployed.
# =============================================================================

# Node 20 (active LTS) matches the version the CI quality gate builds/tests with
# (see .github/workflows/reusable-frontend.yml). Keeping them in lockstep avoids
# "works in CI, breaks in the image" drift and an end-of-life base runtime.
# Pinned by digest for reproducible, supply-chain-resistant builds. The tag is
# kept for readability; the digest is authoritative. To update: re-resolve the
# digest for node:20-alpine and bump it here.
FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293

WORKDIR /app

# Install dependencies first for better layer caching. `npm ci` installs exactly
# what the committed lockfile pins, so the published image matches the tree CI
# verified (reproducible builds); it requires package-lock.json to be present.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./

EXPOSE 5173

# --host exposes the dev server on all interfaces so it is reachable from the
# host machine and other containers.
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
