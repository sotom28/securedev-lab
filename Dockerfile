FROM python:3.11-slim-bookworm

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py ./
COPY templates ./templates

ENV PYTHONUNBUFFERED=1 DATABASE_PATH=/data/securedev.db
EXPOSE 8000
# Servidor de producción (gunicorn) en lugar del servidor de desarrollo de Flask.
# Un solo worker: las métricas de Prometheus viven en la memoria del proceso.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "4", "app:create_app()"]
