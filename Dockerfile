# ULPF — single air-gapped image: perimeter log ingest + processing + the
# management/query API + the React dashboard, all in one process (`ulpf serve`).
#
#   docker build -t ulpf .
#   docker run --rm -p 8080:8080 ulpf        # dashboard + API at http://localhost:8080
#
# Requirement (k): packaged in a container. Requirement (j): once built, it
# needs no network at runtime.

# ---------------------------------------------------------------------------
# Stage 1 — build the dashboard (ui/dist)
# ---------------------------------------------------------------------------
FROM node:20-slim AS ui-builder

WORKDIR /ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci
COPY ui/ ./
RUN npm run build          # -> /ui/dist

# ---------------------------------------------------------------------------
# Stage 2 — the Python application
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    # tells ulpf/api/app.py where the built dashboard lives in this image
    ULPF_UI_DIST=/app/ui/dist

WORKDIR /app

# install the package (deps first for layer caching)
COPY pyproject.toml README.md ./
COPY ulpf/ ./ulpf/
RUN pip install --no-cache-dir .

# runtime config + the pre-built dashboard
COPY configs/ ./configs/
COPY --from=ui-builder /ui/dist ./ui/dist

# non-root
RUN useradd --create-home --uid 10001 ulpf \
    && mkdir -p /app/data/runtime \
    && chown -R ulpf:ulpf /app
USER ulpf

EXPOSE 8080 514/udp 514/tcp 8081

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8080/health').status==200 else 1)"

CMD ["ulpf", "serve"]
