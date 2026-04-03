FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PORTHOUND_ROLE=master \
    PORTHOUND_HOST=0.0.0.0 \
    PORTHOUND_PORT=45678 \
    PORTHOUND_DB_PATH=/data/Master.db

RUN adduser --disabled-password --gecos "" appuser \
    && mkdir -p /data \
    && chown -R appuser:appuser /data

COPY . /app

USER appuser

VOLUME ["/data"]
EXPOSE 45678

CMD ["python", "manage.py"]
