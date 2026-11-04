# IoC Sentinel - sandbox browser image
# Credential-less, non-root, read-only-rootfs friendly. One container per URL.
FROM mcr.microsoft.com/playwright/python:v1.55.0-noble

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    HOME=/tmp \
    OUT_DIR=/tmp/out

# Pin the client to the browser build shipped in the base image.
RUN pip install --no-cache-dir --break-system-packages playwright==1.55.0 \
 && rm -rf /root/.cache

WORKDIR /opt/worker
COPY worker.py /opt/worker/worker.py
RUN chmod 0555 /opt/worker/worker.py

# pwuser (uid 1001) ships with the Playwright image.
USER pwuser

ENTRYPOINT ["python3", "-I", "/opt/worker/worker.py"]
