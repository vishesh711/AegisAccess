# Single image for the API gateway and the MCP server (different commands).
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app/src:/app/apps/api:/app/apps/mcp_server

WORKDIR /app
COPY requirements.lock /app/requirements.lock
# Hash-pinned install (every transitive dependency pinned + sha256-verified).
# An optional extra CA (corporate/sandbox TLS proxy) can be supplied as a build secret; it is
# used only for this step and never stored in an image layer.
RUN --mount=type=secret,id=extra_ca,required=false \
    if [ -s /run/secrets/extra_ca ]; then export PIP_CERT=/run/secrets/extra_ca; fi; \
    pip install --require-hashes --no-deps -r /app/requirements.lock

COPY src /app/src
COPY apps /app/apps
COPY policies /app/policies

RUN useradd --system --uid 10001 --no-create-home aegis
USER 10001

EXPOSE 8000 8001
CMD ["uvicorn", "aegis_api.main:app_factory", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
