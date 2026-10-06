# syntax=docker/dockerfile:1
FROM node:24-slim AS dashboard
WORKDIR /build
COPY dashboard/package.json dashboard/package-lock.json* ./
RUN npm install
COPY dashboard/ ./
RUN npm run build

FROM python:3.12-slim AS runtime
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml ./
RUN pip install .

COPY backend/ backend/
COPY configs/ configs/
COPY --from=dashboard /build/dist dashboard/dist

ENV HONEYMESH_SERVICE__HOST=0.0.0.0 \
    HONEYMESH_SERVICE__PORT=8000

EXPOSE 8000 2222 8081 9000
CMD ["python", "-m", "uvicorn", "app.main:app", "--app-dir", "backend", "--host", "0.0.0.0", "--port", "8000"]
