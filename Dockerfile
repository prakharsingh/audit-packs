FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
COPY packs ./packs
COPY rules ./rules
RUN pip install --no-cache-dir . checkov semgrep
ENV PACKS_DIR=/app/packs RULES_PATH=/app/rules/weak-cipher.yaml
ENTRYPOINT ["python", "-m", "audit_packs.cli"]
