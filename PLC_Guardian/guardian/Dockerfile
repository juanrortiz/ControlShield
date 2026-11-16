# PLC Guardian control panel (Live Demo + Analyze Captures + Evidence). Lab Mode is disabled in the image
# (it needs raw capture and the isolated lab network): run `python gui.py` natively on the lab host for that.
#
# Build (from the PROJECT ROOT, so the build context is the repo):
#   docker build -t plc-guardian -f guardian/Dockerfile .
# Run, then open http://localhost:8765 (captures mounted read-only at /data so they can never be modified):
#   docker run --rm -p 127.0.0.1:8765:8765 -v "<captures dir>:/data:ro" plc-guardian
#
# The demo needs no host networking: the simulated PLC, the Guardian proxy and the three clients all talk over
# the container's own loopback (Linux allows binding source addresses 127.0.0.10 / .2 / .99).

# ---- stage 1: build the React / AlignUI front end --------------------------------------------------------
FROM node:22-alpine AS web
WORKDIR /web
COPY guardian/webui/package.json guardian/webui/package-lock.json ./
RUN npm ci
COPY guardian/webui/ ./
RUN npm run build

# ---- stage 2: Python runtime -----------------------------------------------------------------------------
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 \
    GUARDIAN_LAB=0 \
    GUARDIAN_WEBUI_DIST=/app/guardian/webui-dist \
    GUARDIAN_DATA=/data
# scapy is only used by analyze / forensics / baseline (pcap reading); the proxy, policy and log are stdlib.
RUN pip install --no-cache-dir scapy \
    && useradd --create-home --uid 1000 guardian \
    && mkdir -p /app/guardian/demo /app/guardian/logs /app/guardian/reports /data \
    && chown -R guardian:guardian /app
WORKDIR /app/guardian
COPY --chown=guardian:guardian guardian/guardian.py guardian/gui.py guardian/config.json ./
COPY --chown=guardian:guardian guardian/plcguard ./plcguard
COPY --chown=guardian:guardian guardian/tools ./tools
COPY --chown=guardian:guardian guardian/guiserver ./guiserver
COPY --from=web --chown=guardian:guardian /web/dist /app/guardian/webui-dist
USER guardian
EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8765/api/state', timeout=2)"
CMD ["python", "gui.py", "--host", "0.0.0.0", "--no-browser"]
