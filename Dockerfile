# ── IC-AGI Distributed Execution Node ──
# Multi-stage build for minimal production image

FROM python:3.13-slim AS base

# Security: run as non-root (UID 10001 for K8s runAsNonRoot validation)
RUN groupadd -r icagi && useradd -r -g icagi -u 10001 -d /app -s /sbin/nologin icagi

WORKDIR /app

# Install dependencies first (cache layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY ic_agi/ ./ic_agi/

# Security: switch to non-root user
USER icagi

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

EXPOSE 8080

# Environment defaults
ENV IC_AGI_NODE_ID="node-0" \
    IC_AGI_NODE_ROLE="full" \
    IC_AGI_NUM_WORKERS="3" \
    IC_AGI_THRESHOLD_K="2" \
    IC_AGI_THRESHOLD_N="3" \
    PORT="8080"

CMD ["python", "-m", "uvicorn", "ic_agi.service:app", "--host", "0.0.0.0", "--port", "8080"]
