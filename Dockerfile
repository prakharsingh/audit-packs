FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY packages ./packages
COPY packs ./packs
COPY rules ./rules
ARG INSTALL_AI=false
RUN pip install --no-cache-dir \
    -e packages/core \
    -e packages/mapping \
    -e packages/evidence \
    -e packages/action \
    checkov semgrep \
    && if [ "$INSTALL_AI" = "true" ]; then pip install --no-cache-dir -e "packages/ai[ai]"; else pip install --no-cache-dir -e packages/ai; fi
ENV PACKS_DIR=/app/packs RULES_PATH=/app/rules
ENTRYPOINT ["python", "-m", "audit_packs_action.cli"]
