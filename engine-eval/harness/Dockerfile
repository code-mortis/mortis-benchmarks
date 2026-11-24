# Historical recipe only: the evaluation entry point now refuses execution.
# Preserved evidence refers to the frozen incumbent image, not the current Mortis image.
ARG BASE_IMAGE=code-mortis:pr44-smoke
FROM ${BASE_IMAGE} AS dependencies
USER root
WORKDIR /app/backend
COPY backend/pyproject.toml backend/uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

FROM dependencies AS evaluation
COPY backend/code_mortis/ /app/backend/code_mortis/
COPY backend/migrations/ /app/backend/migrations/
COPY backend/alembic.ini /app/backend/alembic.ini
COPY scripts/engine_eval/runtime.py scripts/engine_eval/capture.py scripts/engine_eval/scanner_preflight.py scripts/engine_eval/workloads.py /app/evaluation/
RUN uv sync --frozen --no-dev && rm -rf /app/backend/tests /app/backend/.pytest_cache /app/backend/.ruff_cache
ENV PYTHONPATH=/app/backend PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
USER mortis
CMD ["python", "/app/evaluation/runtime.py"]
