# Build context is the repository root so the simulator package can be bundled
# (the API's lab router runs the same scenarios server-side for the UI demo).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

COPY backend/requirements.txt backend/requirements-dev.txt ./
RUN pip install -r requirements-dev.txt

COPY backend/ /app/
COPY simulator/ /app/simulator/
# Realm template, seed script and hosted start script (compose also mounts the first two).
COPY keycloak/ /app/keycloak/
COPY scripts/ /app/scripts/
COPY deploy/render/api-start.sh /app/render-start.sh

RUN useradd --create-home --uid 10001 appuser && chown -R appuser /app
USER appuser

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
