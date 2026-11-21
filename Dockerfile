FROM python:3.11-slim-bookworm

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin appuser \
    && mkdir -p /data && chown appuser:appuser /data
COPY app.py ./
COPY templates ./templates

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 DATABASE_PATH=/data/securedev.db
# La app corre sin privilegios (mínimo privilegio): no como root.
USER appuser
EXPOSE 8000
# Servidor de producción (gunicorn) en lugar del servidor de desarrollo de Flask.
# Un solo worker: las métricas de Prometheus viven en la memoria del proceso.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "4", "app:create_app()"]
