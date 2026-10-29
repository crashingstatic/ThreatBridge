FROM python:3.12-slim

RUN useradd --system --uid 10001 --home /app threatbridge \
 && mkdir -p /data /certs && chown threatbridge /data
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY gunicorn.conf.py .
COPY threatbridge ./threatbridge

ENV TB_EXCLUDE_FILE=/data/exclude.json \
    TB_COMPROMISED_FILE=/data/compromised.json \
    TB_SESSIONS_DIR=/data/sessions \
    TB_PORT=5443 \
    PYTHONUNBUFFERED=1
USER threatbridge
EXPOSE 5443
VOLUME ["/data"]
CMD ["gunicorn", "-c", "gunicorn.conf.py"]
