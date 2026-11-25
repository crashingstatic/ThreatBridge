# Base images are pinned by digest and Python packages come from uv.lock (D24). Dependabot
# proposes updates to both.
FROM ghcr.io/astral-sh/uv:0.13.9@sha256:d3b601f0c7b118bc1753febf7c41cc80981df678445e0254284eecf84db79a7d AS uv

# The locked packages, in a virtual environment built with the same Python as the final image.
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-default-groups

FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
RUN useradd --system --uid 10001 --home /app threatbridge \
 && mkdir -p /data /certs && chown threatbridge /data
WORKDIR /app
COPY --from=build /app/.venv /app/.venv
COPY gunicorn.conf.py .
COPY threatbridge ./threatbridge

ENV PATH=/app/.venv/bin:$PATH \
    TB_EXCLUDE_FILE=/data/exclude.json \
    TB_COMPROMISED_FILE=/data/compromised.json \
    TB_SESSIONS_DIR=/data/sessions \
    TB_PORT=5443 \
    PYTHONUNBUFFERED=1
USER threatbridge
EXPOSE 5443
VOLUME ["/data"]
CMD ["gunicorn", "-c", "gunicorn.conf.py"]
