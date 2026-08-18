# =============================================================================
# SPARKSOC agent harness
#
# Built from the staged python:3.11-slim arm64 image and the offline wheelhouse.
# No network access at build time — everything installs with --no-index.
#
# Build on the management VM:
#   docker build -t sparksoc/harness:1.0.0 \
#     --build-arg BASE=python:3.11-slim \
#     -f Dockerfile ..
# =============================================================================
ARG BASE=python:3.11-slim
FROM ${BASE}

LABEL org.opencontainers.image.title="SPARKSOC Agent Harness" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.description="Airgapped dual-DGX-Spark AI SOC pipeline"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_INDEX=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DO_NOT_TRACK=1

WORKDIR /app

# Offline install from the staged wheelhouse. The wheelhouse is bind-mounted or
# COPY-ed in by the build context; see docs/04-HARNESS-DEPLOY.md.
COPY wheelhouse /wheelhouse
COPY harness/requirements.txt /app/requirements.txt
RUN pip install --no-index --find-links=/wheelhouse -r /app/requirements.txt \
    && rm -rf /wheelhouse /root/.cache

COPY harness/app /app/app
COPY common /opt/sparksoc/common

# Run unprivileged. The harness needs no root capability.
RUN useradd --system --uid 10001 --create-home --shell /usr/sbin/nologin sparksoc \
    && mkdir -p /var/lib/sparksoc/audit /var/lib/sparksoc/exercises /etc/sparksoc \
    && chown -R sparksoc:sparksoc /var/lib/sparksoc /app
USER sparksoc

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=4).status==200 else 1)"

CMD ["uvicorn", "app.agent_harness:app", \
     "--host", "0.0.0.0", "--port", "8080", \
     "--workers", "1", "--timeout-keep-alive", "65", \
     "--no-access-log"]
